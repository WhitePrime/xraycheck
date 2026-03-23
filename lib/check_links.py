"""Fetch links from links.txt: file update date (GitHub API or Last-Modified) and line count."""
import json
import re
import time
import urllib.request
import ssl
from urllib.parse import urlparse, unquote

SSL = ssl.create_default_context()

def parse_github_raw(url: str) -> tuple[str, str, str, str] | None:
    """Return (owner, repo, ref, path) or None."""
    # raw.githubusercontent.com/owner/repo/refs/heads/branch/path or owner/repo/branch/path
    # github.com/owner/repo/raw/refs/heads/branch/path
    url = unquote(url)
    if "raw.githubusercontent.com" in url:
        prefix = "https://raw.githubusercontent.com/"
        if not url.startswith(prefix):
            return None
        rest = url[len(prefix):]
        parts = rest.split("/")
        if len(parts) < 4:
            return None
        owner, repo = parts[0], parts[1]
        if parts[2] == "refs" and len(parts) >= 5 and parts[3] == "heads":
            ref = parts[4]
            path = "/".join(parts[5:])
        else:
            ref = parts[2]
            path = "/".join(parts[3:])
        return (owner, repo, ref, path)
    if "github.com" in url and "/raw/" in url:
        # github.com/owner/repo/raw/refs/heads/main/path
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/raw/(.+)", url)
        if m:
            owner, repo, rest = m.groups()
            parts = rest.split("/")
            if len(parts) >= 3 and parts[0] == "refs" and parts[1] == "heads":
                ref = parts[2]
                path = "/".join(parts[3:])
            elif parts:
                ref = parts[0]
                path = "/".join(parts[1:]) if len(parts) > 1 else ""
            else:
                return None
            return (owner, repo, ref, path)
    return None

def github_file_date(owner: str, repo: str, ref: str, path: str, token: str | None) -> str:
    """Get last commit date for file via GitHub API. Returns YYYY-MM-DD or error string."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits?path={path}&sha={ref}&per_page=1"
    req = urllib.request.Request(api_url)
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "xraycheck")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15, context=SSL) as r:
            data = json.load(r)
            if data and isinstance(data, list) and len(data) > 0:
                commit = data[0]
                date_str = commit.get("commit", {}).get("committer", {}).get("date", "")
                if date_str:
                    return date_str[:10]  # YYYY-MM-DD
    except Exception as e:
        return f"error: {type(e).__name__}"
    return ""

def get_info(url: str, github_token: str | None = None) -> tuple[str, int]:
    """Return (date_str, line_count). Date is file last-updated (GitHub API or Last-Modified)."""
    url = url.strip()
    if not url or url.startswith("#"):
        return "", 0
    date_str = ""
    line_count = 0
    gh = parse_github_raw(url)
    if gh:
        owner, repo, ref, path = gh
        date_str = github_file_date(owner, repo, ref, path, github_token)
        if not date_str or date_str.startswith("error"):
            pass  # fallback to HTTP below
        else:
            # get line count by fetching content
            try:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "Mozilla/5.0 (compatible; xraycheck)")
                with urllib.request.urlopen(req, timeout=15, context=SSL) as r:
                    text = r.read().decode("utf-8", errors="replace")
                    line_count = len([l for l in text.splitlines() if l.strip()])
            except Exception:
                pass
            return date_str, line_count
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; xraycheck)")
        with urllib.request.urlopen(req, timeout=15, context=SSL) as r:
            lm = r.headers.get("Last-Modified") or r.headers.get("Date", "")
            if lm:
                # parse RFC 2822 to YYYY-MM-DD if possible
                from email.utils import parsedate_to_datetime
                try:
                    dt = parsedate_to_datetime(lm)
                    date_str = dt.strftime("%Y-%m-%d")
                except Exception:
                    date_str = lm[:16] if len(lm) > 16 else lm
            text = r.read().decode("utf-8", errors="replace")
            line_count = len([l for l in text.splitlines() if l.strip()])
    except Exception as e:
        date_str = f"error: {type(e).__name__}"
    return date_str, line_count

def main():
    import argparse
    import os

    p = argparse.ArgumentParser(description="Check sources: last update date and config count (non-empty lines).")
    p.add_argument("--in", dest="in_file", default="links.txt", help="Input file with one URL per line.")
    p.add_argument("--out", dest="out_file", default="", help="Output markdown file. If empty, prints to stdout.")
    args = p.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    with open(args.in_file, "r", encoding="utf-8") as f:
        urls = [u.strip().split("#")[0].strip() for u in f if u.strip()]
    urls = list(dict.fromkeys(urls))

    lines: list[str] = []
    lines.append("Link|Date|Configs")
    lines.append("---|---:|---:")
    for i, url in enumerate(urls):
        if i > 0 and parse_github_raw(url):
            time.sleep(0.5)  # avoid GitHub API rate limit
        date_str, line_count = get_info(url, token)
        lines.append(f"{url}|{date_str}|{line_count}")

    out_text = "\n".join(lines) + "\n"
    if args.out_file:
        with open(args.out_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(out_text)
    else:
        print(out_text, end="")

if __name__ == "__main__":
    main()
