#!/usr/bin/env python3
"""
Log File Analyzer (beginner-friendly, no external deps)

Features:
- Input: JSONL (newline-delimited), JSON array/object (e.g., Graph API with top-level "value"), or CSV with headers
- Filters: --since / --until (ISO or common datetime formats)
- Metrics: total events, failed vs success counts, top IPs/users, hourly histogram
- Exports: optional CSVs for top IPs/users and histogram

Usage examples:
  python3 log_analyzer.py -i sample.jsonl --format auto
  python3 log_analyzer.py -i sample.json --format auto  # JSON array or Graph JSON
  python3 log_analyzer.py -i sample.csv --format csv --since 2025-09-01
  python3 log_analyzer.py -i sample.jsonl --top 10 --out-dir out
"""

import argparse, csv, json, os, re, sys
# Optional colored console output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
    # Force-enable colors in some terminals (e.g., CI or integrated terminals)
    console = Console(force_terminal=True, color_system="truecolor")
except Exception:
    RICH_AVAILABLE = False
    console = None
    Table = None
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# Basic ANSI colors (used when Rich isn't available)
ANSI_ENABLE = sys.stdout.isatty()
ANSI = {
    "reset": "\x1b[0m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "bright_red": "\x1b[91m",
    "bright_green": "\x1b[92m",
    "bright_yellow": "\x1b[93m",
    "bright_blue": "\x1b[94m",
    "bright_magenta": "\x1b[95m",
    "bright_cyan": "\x1b[96m",
}

# Palette for top-10 rows (cycled if more)
TOP10_ANSI_PALETTE = [
    ANSI["bright_red"], ANSI["bright_green"], ANSI["bright_yellow"], ANSI["bright_blue"], ANSI["bright_magenta"],
    ANSI["bright_cyan"], ANSI["red"], ANSI["green"], ANSI["yellow"], ANSI["blue"],
]

def colorize(text, color_code, enable=True):
    if not enable:
        return str(text)
    return f"{color_code}{text}{ANSI['reset']}"

# --------- Defaults & helpers ---------

DEFAULT_FIELD_MAP = {
    "timestamp": ["timestamp", "@timestamp", "time", "date", "created"],
    "action":    ["action", "event", "result", "status", "outcome"],
    "ip":        ["ip", "ip_address", "sourceIp", "src_ip", "client_ip"],
    "user":      ["user", "username", "userPrincipalName", "upn", "account", "actor"],
    "severity":  ["severity", "level"]
}

# Classify failures/success by keywords (case-insensitive)
DEFAULT_FAIL_PATTERNS = [r"fail", r"denied", r"invalid", r"error", r"blocked", r"risky"]
DEFAULT_SUCCESS_PATTERNS = [r"success", r"succeeded", r"ok", r"passed"]

def compile_patterns(words):
    return [re.compile(w, re.IGNORECASE) for w in words]

FAIL_RE = compile_patterns(DEFAULT_FAIL_PATTERNS)
SUCC_RE = compile_patterns(DEFAULT_SUCCESS_PATTERNS)

DATE_FORMATS = [
    "%Y-%m-%d",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
]

def parse_when(s):
    """Try multiple datetime formats; return datetime or None."""
    if not s:
        return None
    # quick try: ISO 8601
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        pass
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

def get_field(rec, preferred, fallbacks):
    """Get rec[preferred] if present, else first non-empty from fallbacks."""
    if preferred and preferred in rec and rec[preferred] not in (None, ""):
        return rec[preferred]
    for k in fallbacks:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return None

def classify(action_text, severity_text):
    """Return 'failed', 'success', or 'unknown'."""
    t = (action_text or "") + " " + (severity_text or "")
    for rx in FAIL_RE:
        if rx.search(t):
            return "failed"
    for rx in SUCC_RE:
        if rx.search(t):
            return "success"
    return "unknown"

# --------- Core analyzer ---------

def _iterate_parsed_json(obj):
    """Yield dict-like records from parsed JSON.
    Supports:
    - list of dicts
    - dict with an array at keys like 'value', 'records', 'items', 'data', 'results', 'logs', 'events', 'entries'
    - single dict record
    """
    candidate_keys = [
        "value", "values", "records", "items", "data", "results", "logs", "events", "entries"
    ]
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                yield item
    elif isinstance(obj, dict):
        for k in candidate_keys:
            v = obj.get(k)
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        yield item
                return
        # Fallback: single-record dict
        yield obj

def load_records(path, fmt):
    # Decide base mode from extension if auto
    if fmt == "auto":
        ext = os.path.splitext(path.lower())[1]
        if ext == ".csv":
            fmt = "csv"
        else:
            fmt = "json"  # try full JSON first, then fallback to JSONL

    # CSV straightforward
    if fmt == "csv":
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield row
        return

    # JSON/JSONL: try parse whole file as JSON, fallback to JSONL per line
    if fmt in ("json", "jsonl", "auto"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            content_stripped = content.lstrip()
            # Quick sanity: must look like JSON to attempt full parse
            if content_stripped.startswith("[") or content_stripped.startswith("{"):
                parsed = json.loads(content)
                yielded = False
                for rec in _iterate_parsed_json(parsed):
                    yielded = True
                    yield rec
                if yielded:
                    return
        except Exception:
            # Fallback to JSONL below
            pass

        # JSONL fallback (line-by-line)
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        return

    raise ValueError(f"Unsupported format: {fmt}")

def analyze(files, fmt, fields, since, until, top_n, out_dir, use_rich, use_ansi):
    counters = {
        "total": 0,
        "failed": 0,
        "success": 0,
        "unknown": 0,
    }
    top_ips = Counter()
    top_users = Counter()
    by_hour_failed = Counter()
    times_seen = []

    for path in files:
        for rec in load_records(path, fmt):
            ts_raw = get_field(rec, fields["timestamp"], DEFAULT_FIELD_MAP["timestamp"])
            user = get_field(rec, fields["user"], DEFAULT_FIELD_MAP["user"])
            ip = get_field(rec, fields["ip"], DEFAULT_FIELD_MAP["ip"])
            action = get_field(rec, fields["action"], DEFAULT_FIELD_MAP["action"])
            sev = get_field(rec, fields["severity"], DEFAULT_FIELD_MAP["severity"])

            ts = parse_when(str(ts_raw)) if ts_raw else None
            # Filter by window if we have a timestamp
            if since and ts and ts < since:
                continue
            if until and ts and ts > until:
                continue

            kind = classify(str(action), str(sev))
            counters["total"] += 1
            counters[kind] += 1

            if kind == "failed":
                if ip: top_ips[ip] += 1
                if user: top_users[user] += 1
                if ts:
                    bucket = ts.replace(minute=0, second=0, microsecond=0)
                    by_hour_failed[bucket] += 1
            if ts:
                times_seen.append(ts)

    # Prepare hourly histogram (limit width sensibly)
    histogram = []
    if by_hour_failed:
        all_hours = sorted(by_hour_failed.keys())
        start = all_hours[0]
        end = all_hours[-1]
        # Cap to last 24 hours for readability if very large
        if end - start > timedelta(hours=48):
            start = end - timedelta(hours=24)
        cur = start
        while cur <= end:
            histogram.append((cur, by_hour_failed.get(cur, 0)))
            cur += timedelta(hours=1)

    # Print report
    if use_rich and console is not None and RICH_AVAILABLE and Table is not None:
        console.rule("Log Analyzer")
        console.print("[dim]Rich mode:[/] [green]ON[/]")
        console.print("[bold cyan]Summary[/]")

        # Build a summary table
        summary = Table(show_header=False, expand=False, box=None)
        success_rate = (counters['success'] / counters['total'] * 100.0) if counters['total'] else 0.0
        summary.add_row("Total", f"[white]{counters['total']}[/]")
        summary.add_row("Failures", f"[bold red]{counters['failed']}[/]")
        summary.add_row("Success", f"[bold green]{counters['success']}[/]")
        if counters['unknown'] > 0:
            summary.add_row("Unknown", f"[yellow]{counters['unknown']}[/]")
        summary.add_row("Success Rate", f"[bold]{success_rate:.1f}%[/]")
        console.print(summary)

        # Time info
        if since:
            console.print(f"[dim]Since:[/] {since.isoformat(sep=' ')}")
        if until:
            console.print(f"[dim]Until:[/] {until.isoformat(sep=' ')}")
        if times_seen:
            console.print(f"[dim]Time span in data:[/] {min(times_seen)} → {max(times_seen)}")

        console.rule()

        def print_top_rich(title, cnt: Counter):
            if not RICH_AVAILABLE or Table is None or console is None:
                return
            table = Table(title=title, header_style="bold cyan", title_style="bold", expand=False)
            table.add_column("#", style="dim", width=3, justify="right")
            table.add_column("Key", style="white")
            table.add_column("Count", style="bold", justify="right")
            if not cnt:
                table.add_row("-", "[dim](none)[/]", "0")
            else:
                # Per-rank color accents
                rich_palette = [
                    "bold red", "bold green", "bold yellow", "bold blue", "bold magenta",
                    "bold cyan", "red", "green", "yellow", "blue",
                ]
                for i, (k, v) in enumerate(cnt.most_common(top_n), 1):
                    color = rich_palette[(i - 1) % len(rich_palette)]
                    table.add_row(f"[{color}]{i}[/]", f"[{color}]{k}[/]", f"[{color}]{v}[/]")
            console.print(table)

        print_top_rich(f"Top {top_n} IPs (by failures)", top_ips)
        print_top_rich(f"Top {top_n} Users (by failures)", top_users)

        if histogram:
            hist_table = Table(title="Hourly failure histogram", header_style="bold cyan", title_style="bold")
            hist_table.add_column("Hour", style="dim")
            hist_table.add_column("Failures", justify="right")
            hist_table.add_column("Bar")
            for t, n in histogram:
                bar = "█" * min(n, 40)
                hist_table.add_row(f"{t:%Y-%m-%d %H:00}", f"{n}", f"[red]{bar}[/]")
            console.print(hist_table)
    else:
        print("\n=== Log Analysis Summary ===")
        if since: print(f"Since: {since.isoformat(sep=' ')}")
        if until: print(f"Until: {until.isoformat(sep=' ')}")
        if times_seen:
            print(f"Time span in data: {min(times_seen)} → {max(times_seen)}")
        print(f"Total events:   {counters['total']}")
        print(
            f"Failures:       " +
            colorize(counters['failed'], ANSI['red'], enable=use_ansi and ANSI_ENABLE)
        )
        print(
            f"Success:        " +
            colorize(counters['success'], ANSI['green'], enable=use_ansi and ANSI_ENABLE)
        )
        if counters['unknown'] > 0:
            print(
                f"Unknown:        " +
                colorize(counters['unknown'], ANSI['yellow'], enable=use_ansi and ANSI_ENABLE) +
                "  (could not classify)"
            )

        def print_top(title, cnt: Counter):
            print(f"\nTop {top_n} {title}:")
            if not cnt:
                print("  (none)")
                return
            for i, (k, v) in enumerate(cnt.most_common(top_n), 1):
                color = TOP10_ANSI_PALETTE[(i - 1) % len(TOP10_ANSI_PALETTE)]
                rank = colorize(f"{i:>2}", color, enable=use_ansi and ANSI_ENABLE)
                key = colorize(f"{k:<25}", color, enable=use_ansi and ANSI_ENABLE)
                val = colorize(str(v), color, enable=use_ansi and ANSI_ENABLE)
                print(f"  {rank}. {key} {val}")

        print_top("IPs (by failures)", top_ips)
        print_top("Users (by failures)", top_users)

        if histogram:
            print("\nHourly failure histogram:")
            for t, n in histogram:
                bar_raw = "#" * min(n, 40)
                bar = colorize(bar_raw, ANSI['red'], enable=use_ansi and ANSI_ENABLE)
                n_col = colorize(f"{n:>3}", ANSI['red'], enable=use_ansi and ANSI_ENABLE)
                print(f"  {t:%Y-%m-%d %H:00} | {n_col} {bar}")

    # Exports
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        # top IPs
        with open(os.path.join(out_dir, "top_ips.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["ip", "failed_count"])
            for ip, n in top_ips.most_common(top_n):
                w.writerow([ip, n])
        # top users
        with open(os.path.join(out_dir, "top_users.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["user", "failed_count"])
            for user, n in top_users.most_common(top_n):
                w.writerow([user, n])
        # histogram
        with open(os.path.join(out_dir, "hourly_histogram.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["hour", "failed_count"])
            for t, n in histogram:
                w.writerow([t.isoformat(sep=" "), n])
        if use_rich and console is not None:
            console.print(f"\n[dim]Exported CSVs to:[/] [bold]{out_dir}[/]")
        else:
            print(f"\nExported CSVs to: {out_dir}")

def main():
    p = argparse.ArgumentParser(description="Simple Log File Analyzer")
    p.add_argument("-i", "--input", required=True, nargs="+", help="Input file(s): JSONL or CSV")
    p.add_argument("--format", choices=["auto", "jsonl", "csv"], default="auto", help="Input format (auto by extension)")
    p.add_argument("--since", help="Filter: only events on/after this time (e.g. 2025-09-01 or 2025-09-01T12:00)")
    p.add_argument("--until", help="Filter: only events on/before this time")
    p.add_argument("--top", type=int, default=5, help="How many top IPs/users to show/export")
    p.add_argument("--out-dir", help="Directory to write CSV summaries (optional)")
    # Field mapping (optional)
    p.add_argument("--field-timestamp", default=None, help="Column/key name for timestamp")
    p.add_argument("--field-action", default=None, help="Column/key name for action/result")
    p.add_argument("--field-ip", default=None, help="Column/key name for IP/source")
    p.add_argument("--field-user", default=None, help="Column/key name for user")
    p.add_argument("--field-severity", default=None, help="Column/key name for severity/level")
    p.add_argument("--no-color", action="store_true", help="Disable colored output (Rich/ANSI)")
    p.add_argument("--color", action="store_true", help="Force colored output if possible")
    args = p.parse_args()

    # Decide colorization mode
    want_color = not args.no_color and (args.color or True)
    use_rich = False
    if want_color and RICH_AVAILABLE:
        use_rich = True  # prefer Rich if available
    use_ansi = want_color and not use_rich  # fallback to ANSI if no Rich

    since = parse_when(args.since) if args.since else None
    until = parse_when(args.until) if args.until else None

    fields = {
        "timestamp": args.field_timestamp,
        "action": args.field_action,
        "ip": args.field_ip,
        "user": args.field_user,
        "severity": args.field_severity,
    }

    try:
        analyze(args.input, args.format, fields, since, until, args.top, args.out_dir, use_rich, use_ansi)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)

if __name__ == "__main__":
    main()
