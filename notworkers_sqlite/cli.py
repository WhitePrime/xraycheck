from __future__ import annotations

import argparse
from pathlib import Path

from .store import (
    DB_PATH,
    export_to_flat,
    get_stats,
    migrate_from_flat,
    expire_old,
    prune_to_max,
    init_db,
)


def cmd_migrate_from_flat(args: argparse.Namespace) -> None:
    flat_path = Path(args.flat) if args.flat else Path("configs") / "notworkers"
    db_path = Path(args.db) if args.db else DB_PATH
    inserted, updated = migrate_from_flat(flat_path=flat_path, db_path=db_path)
    print(
        f"Migration from flat '{flat_path}' to SQLite '{db_path}': "
        f"inserted {inserted}, updated {updated}"
    )


def cmd_summary(args: argparse.Namespace) -> None:
    db_path = Path(args.db) if args.db else DB_PATH
    if not db_path.is_file():
        print(f"No SQLite notworkers DB at '{db_path}'")
        return
    import sqlite3

    conn = init_db(db_path)
    try:
        stats = get_stats(conn)
        print("SQLite notworkers summary:")
        print(f"  DB path       : {db_path}")
        print(f"  total records : {stats.total}")
        print(f"  first_seen min: {stats.min_first_seen}")
        print(f"  last_seen max : {stats.max_last_seen}")
    finally:
        conn.close()


def cmd_export_flat(args: argparse.Namespace) -> None:
    db_path = Path(args.db) if args.db else DB_PATH
    flat_path = Path(args.flat) if args.flat else Path("configs") / "notworkers_from_db"
    count = export_to_flat(db_path=db_path, flat_path=flat_path)
    print(
        f"Exported {count} records from SQLite '{db_path}' "
        f"to flat file '{flat_path}'"
    )


def cmd_expire(args: argparse.Namespace) -> None:
    db_path = Path(args.db) if args.db else DB_PATH
    max_age_days = int(args.days)
    import sqlite3

    conn = init_db(db_path)
    try:
        removed = expire_old(conn, max_age_days=max_age_days)
        print(
            f"Expired {removed} notworkers entries older than {max_age_days} days "
            f"in '{db_path}'"
        )
    finally:
        conn.close()


def cmd_prune(args: argparse.Namespace) -> None:
    db_path = Path(args.db) if args.db else DB_PATH
    max_age_days = int(args.days)
    max_rows = int(args.max_rows)

    conn = init_db(db_path)
    try:
        cur = conn.execute("SELECT COUNT(*) FROM notworkers")
        total_before = cur.fetchone()[0] or 0
        print(f"Before prune: total={total_before}")

        removed_ttl = 0
        if max_age_days > 0:
            removed_ttl = expire_old(conn, max_age_days=max_age_days)
        print(f"expire_old: removed {removed_ttl} rows older than {max_age_days} days")

        removed_extra = 0
        if max_rows > 0:
            removed_extra = prune_to_max(conn, max_rows=max_rows)
        print(f"prune_to_max: removed {removed_extra} extra rows above {max_rows}")

        cur = conn.execute("SELECT COUNT(*), MIN(first_seen), MAX(last_seen) FROM notworkers")
        total_after, min_first, max_last = cur.fetchone()
        print(
            "After prune: "
            f"total={total_after}, min_first={min_first}, max_last={max_last}"
        )

        print("Running VACUUM to shrink file...")
        conn.execute("VACUUM")
    finally:
        conn.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CLI для экспериментального SQLite-хранилища notworkers"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_migrate = subparsers.add_parser(
        "migrate-from-flat",
        help="мигрировать текущий configs/notworkers в SQLite",
    )
    p_migrate.add_argument(
        "--flat",
        type=str,
        help="путь к исходному текстовому notworkers (по умолчанию configs/notworkers)",
    )
    p_migrate.add_argument(
        "--db",
        type=str,
        help="путь к SQLite-БД (по умолчанию configs/notworkers.db)",
    )
    p_migrate.set_defaults(func=cmd_migrate_from_flat)

    p_summary = subparsers.add_parser(
        "summary",
        help="показать краткую статистику по SQLite notworkers",
    )
    p_summary.add_argument(
        "--db",
        type=str,
        help="путь к SQLite-БД (по умолчанию configs/notworkers.db)",
    )
    p_summary.set_defaults(func=cmd_summary)

    p_export = subparsers.add_parser(
        "export-flat",
        help="экспортировать SQLite notworkers в текстовый файл",
    )
    p_export.add_argument(
        "--db",
        type=str,
        help="путь к SQLite-БД (по умолчанию configs/notworkers.db)",
    )
    p_export.add_argument(
        "--flat",
        type=str,
        help=(
            "путь к целевому текстовому файлу "
            "(по умолчанию configs/notworkers_from_db)"
        ),
    )
    p_export.set_defaults(func=cmd_export_flat)

    p_expire = subparsers.add_parser(
        "expire",
        help="TTL-чистка записей в SQLite notworkers по last_seen",
    )
    p_expire.add_argument(
        "--db",
        type=str,
        help="путь к SQLite-БД (по умолчанию configs/notworkers.db)",
    )
    p_expire.add_argument(
        "--days",
        type=int,
        required=True,
        help="сколько дней хранить записи (удаляются старше этого значения)",
    )
    p_expire.set_defaults(func=cmd_expire)

    p_prune = subparsers.add_parser(
        "prune",
        help="агрессивная чистка: TTL + лимит по числу записей + VACUUM",
    )
    p_prune.add_argument(
        "--db",
        type=str,
        help="путь к SQLite-БД (по умолчанию configs/notworkers.db)",
    )
    p_prune.add_argument(
        "--days",
        type=int,
        default=0,
        help="TTL в днях (0 = не использовать TTL)",
    )
    p_prune.add_argument(
        "--max-rows",
        type=int,
        default=0,
        help="максимальное число записей (0 = не ограничивать)",
    )
    p_prune.set_defaults(func=cmd_prune)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return
    func(args)


if __name__ == "__main__":
    main()

