from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional

# Путь по умолчанию для SQLite-хранилища notworkers
DB_PATH = Path("configs") / "notworkers.db"

# Формат времени: ISO-8601 UTC, чтобы сортировка по строке совпадала со временем
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utc_now_str() -> str:
    return datetime.utcnow().strftime(DATETIME_FORMAT)


def init_db(db_path: Path | str = DB_PATH) -> sqlite3.Connection:
    """
    Создаёт (при необходимости) файл БД и таблицу notworkers, возвращает подключение.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notworkers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            raw TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            fail_count INTEGER NOT NULL DEFAULT 1,
            source TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_notworkers_last_seen ON notworkers(last_seen)"
    )
    conn.commit()
    return conn


def upsert_notworker(
    conn: sqlite3.Connection,
    key: str,
    raw: str,
    source: Optional[str] = None,
    seen_at: Optional[str] = None,
) -> None:
    """
    Добавляет или обновляет запись о notworker по нормализованному ключу.
    """
    if not key:
        return
    if seen_at is None:
        seen_at = _utc_now_str()

    conn.execute(
        """
        INSERT INTO notworkers (key, raw, first_seen, last_seen, fail_count, source)
        VALUES (?, ?, ?, ?, 1, ?)
        ON CONFLICT(key) DO UPDATE SET
            raw = excluded.raw,
            last_seen = excluded.last_seen,
            fail_count = notworkers.fail_count + 1,
            source = COALESCE(excluded.source, notworkers.source)
        """,
        (key, raw, seen_at, seen_at, source),
    )


def is_notworker(conn: sqlite3.Connection, key: str) -> bool:
    """
    Проверяет, есть ли нормализованный ключ в хранилище.
    """
    if not key:
        return False
    cur = conn.execute("SELECT 1 FROM notworkers WHERE key = ? LIMIT 1", (key,))
    return cur.fetchone() is not None


def expire_old(conn: sqlite3.Connection, max_age_days: int) -> int:
    """
    Удаляет записи, у которых last_seen старше max_age_days дней.
    Возвращает количество удалённых строк.
    """
    if max_age_days <= 0:
        return 0
    cutoff = datetime.utcnow() - timedelta(days=max_age_days)
    cutoff_str = cutoff.strftime(DATETIME_FORMAT)
    cur = conn.execute("DELETE FROM notworkers WHERE last_seen < ?", (cutoff_str,))
    conn.commit()
    return cur.rowcount


def prune_to_max(conn: sqlite3.Connection, max_rows: int) -> int:
    """
    Оставляет не более max_rows самых свежих записей (по last_seen).
    Возвращает количество удалённых строк.
    """
    if max_rows <= 0:
        return 0
    cur = conn.execute("SELECT COUNT(*) FROM notworkers")
    total = cur.fetchone()[0] or 0
    if total <= max_rows:
        return 0
    to_delete = total - max_rows
    cur = conn.execute(
        """
        DELETE FROM notworkers
        WHERE id IN (
            SELECT id FROM notworkers
            ORDER BY last_seen ASC
            LIMIT ?
        )
        """,
        (to_delete,),
    )
    conn.commit()
    return cur.rowcount


@dataclass
class NotworkersStats:
    total: int
    min_first_seen: Optional[str]
    max_last_seen: Optional[str]


def get_stats(conn: sqlite3.Connection) -> NotworkersStats:
    """
    Возвращает простую сводную статистику по таблице notworkers.
    """
    cur = conn.execute(
        "SELECT COUNT(*), MIN(first_seen), MAX(last_seen) FROM notworkers"
    )
    row = cur.fetchone()
    if not row:
        return NotworkersStats(total=0, min_first_seen=None, max_last_seen=None)
    total, min_first_seen, max_last_seen = row
    return NotworkersStats(
        total=int(total),
        min_first_seen=min_first_seen,
        max_last_seen=max_last_seen,
    )


def migrate_from_flat(
    flat_path: Path | str = Path("configs") / "notworkers",
    db_path: Path | str = DB_PATH,
    source: str = "flat",
) -> tuple[int, int]:
    """
    Однократная/повторяемая миграция содержимого текстового configs/notworkers в SQLite.

    Возвращает (inserted, updated).
    """
    from lib.parsing import load_notworkers_with_lines  # импортируем по требованию

    flat = Path(flat_path)
    if not flat.is_file():
        return 0, 0

    existing_set, normalized_to_full = load_notworkers_with_lines(str(flat))
    if not normalized_to_full:
        return 0, 0

    with closing(init_db(db_path)) as conn:
        inserted = 0
        updated = 0
        for norm, full in normalized_to_full.items():
            cur = conn.execute(
                "SELECT 1 FROM notworkers WHERE key = ? LIMIT 1", (norm,)
            )
            exists = cur.fetchone() is not None
            upsert_notworker(conn, norm, full, source=source)
            if exists:
                updated += 1
            else:
                inserted += 1
        conn.commit()
        return inserted, updated


def export_to_flat(
    db_path: Path | str = DB_PATH,
    flat_path: Path | str = Path("configs") / "notworkers_from_db",
) -> int:
    """
    Экспортирует содержимое notworkers из БД в текстовый файл (по полю raw).
    Возвращает количество записей.
    """
    db = Path(db_path)
    if not db.is_file():
        return 0

    flat = Path(flat_path)
    flat.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(str(db))) as conn, flat.open(
        "w", encoding="utf-8"
    ) as f:
        cur = conn.execute(
            "SELECT raw FROM notworkers ORDER BY key"
        )
        count = 0
        for (raw,) in cur:
            # raw уже содержит перевод строки (как в исходном файле notworkers)
            if raw.endswith("\n"):
                f.write(raw)
            else:
                f.write(raw + "\n")
            count += 1
        return count

