#!/usr/bin/env python3
"""
logsearch.py — Flexible, stdlib-only log parser for apps & web servers (Windows & Linux).

Now with:
- Automatic field extraction using named-group regexes (field_patterns)
- Follow mode (--follow / -f) to tail files like `tail -f` (multi-file, rotation-aware best-effort)
- HAProxy regex template provided in sample config

Other features:
- Edit search params in config.json (no code changes needed).
- Keywords and/or regex patterns; match ANY or ALL.
- Include/exclude files via globs; reads .gz files (follow mode skips .gz).
- Optional time filtering if your logs contain timestamps.
- Outputs to console (pretty), CSV, or JSONL.
- Cross-platform paths; no 3rd-party deps.

Usage
  python logsearch.py --config config.json
  python logsearch.py --config config.json --since "2025-08-01 00:00:00" --until "2025-08-18 23:59:59" -f
  python logsearch.py --keyword ERROR --regex "timeout|connection reset" --any --format jsonl --output hits.jsonl
"""

import argparse
import json
import re
import sys
import gzip
import io
from pathlib import Path
from datetime import datetime, timezone
import csv

def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def find_files(include_globs, exclude_globs) -> list[Path]:
    import glob, os
    files: list[Path] = []
    for pattern in include_globs:
        expanded = os.path.expanduser(os.path.expandvars(pattern))
        # Use glob.glob for both abs and rel
        for p in glob.glob(expanded, recursive=True):
            pp = Path(p)
            if pp.exists() and pp.is_file():
                files.append(pp)
    # Dedup
    files = sorted({Path(str(x)) for x in files})
    # Exclude
    if exclude_globs:
        excluded = set()
        for ex in exclude_globs:
            for p in glob.glob(os.path.expanduser(os.path.expandvars(ex)), recursive=True):
                excluded.add(Path(p))
        files = [f for f in files if f not in excluded]
    return files

def open_maybe_gzip(path: Path, encoding: str):
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding=encoding, errors="replace", newline="")
    return path.open("r", encoding=encoding, errors="replace", newline="")

def compile_patterns(keywords: list[str], regexes: list[str], ignore_case: bool):
    flags = re.IGNORECASE if ignore_case else 0
    kw_patterns = [re.compile(re.escape(k), flags) for k in keywords] if keywords else []
    rx_patterns = [re.compile(r, flags) for r in regexes] if regexes else []
    return kw_patterns, rx_patterns

def extract_timestamp(line: str, ts_regex: re.Pattern|None, ts_fmt: str|None, assume_tz: str) -> datetime|None:
    if not ts_regex or not ts_fmt:
        return None
    m = ts_regex.search(line)
    if not m:
        return None
    ts_str = m.group("ts") if "ts" in m.groupdict() else m.group(0)
    try:
        dt = datetime.strptime(ts_str, ts_fmt)
        if assume_tz.lower() == "utc":
            return dt.replace(tzinfo=timezone.utc)
        elif assume_tz.lower() == "local":
            return dt.astimezone()
        else:
            return dt
    except Exception:
        return None

def match_line(line: str, kw_patterns, rx_patterns, match_mode: str) -> (bool, str|None):
    reasons = []
    for p in kw_patterns:
        if p.search(line):
            reasons.append(f"kw:{p.pattern}")
    for p in rx_patterns:
        if p.search(line):
            reasons.append(f"re:{p.pattern}")
    if not reasons:
        return False, None
    if match_mode == "all":
        ok = True
        if kw_patterns:
            ok &= any(p.search(line) for p in kw_patterns)
        if rx_patterns:
            ok &= any(p.search(line) for p in rx_patterns)
        return ok, reasons[0] if ok else None
    return True, reasons[0]

def iter_lines(files, encoding: str):
    for f in files:
        try:
            with open_maybe_gzip(f, encoding) as fh:
                for idx, line in enumerate(fh, start=1):
                    yield f, idx, line.rstrip("\\n")
        except Exception as e:
            print(f"[WARN] Could not read {f}: {e}", file=sys.stderr)

def within_window(ts: datetime|None, since: datetime|None, until: datetime|None) -> bool:
    if since is None and until is None:
        return True
    if ts is None:
        return False
    if since and ts < since:
        return False
    if until and ts > until:
        return False
    return True

def parse_dt(s: str|None) -> datetime|None:
    if not s:
        return None
    fmts = ["%Y-%m-%d", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"]
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt).astimezone()
        except ValueError:
            continue
    raise ValueError(f"Could not parse datetime: {s}")

def _read_new_lines(fp, pos):
    fp.seek(pos)
    lines = fp.readlines()
    new_pos = fp.tell()
    return new_pos, [ln.rstrip("\\n") for ln in lines]

def _tail_files(files, encoding, callback, poll_interval=0.5):
    import time, os
    state = {}
    def _open(path: Path):
        try:
            if str(path).endswith(".gz"):
                print(f"[WARN] Follow mode skips gzip file: {path}", file=sys.stderr)
                return None
            fh = path.open("r", encoding=encoding, errors="replace", newline="")
            st = path.stat()
            return {"fh": fh, "pos": fh.seek(0, os.SEEK_END), "lineno": 0, "stat": (st.st_ino, st.st_size)}
        except Exception as e:
            print(f"[WARN] Cannot open {path}: {e}", file=sys.stderr)
            return None

    for f in files:
        st = _open(f)
        if st:
            state[f] = st

    while True:
        for f, st in list(state.items()):
            try:
                cur_stat = f.stat()
                # handle truncation/rotation
                if cur_stat.st_size < st["stat"][1]:
                    try:
                        st["fh"].close()
                    except Exception:
                        pass
                    st2 = _open(f)
                    if st2:
                        state[f] = st2
                        st = st2
                    else:
                        del state[f]
                        continue
                new_pos, lines = _read_new_lines(st["fh"], st["pos"])
                if lines:
                    st["pos"] = new_pos
                    st["stat"] = (cur_stat.st_ino, new_pos)
                    for ln in lines:
                        st["lineno"] += 1
                        callback(f, st["lineno"], ln)
                else:
                    st["stat"] = (cur_stat.st_ino, cur_stat.st_size)
            except FileNotFoundError:
                try:
                    st["fh"].close()
                except Exception:
                    pass
                del state[f]
            except Exception as e:
                print(f"[WARN] Tail error for {f}: {e}", file=sys.stderr)
        time.sleep(poll_interval)

def main():
    ap = argparse.ArgumentParser(description="Search application and webserver logs with keywords/regex, extract fields, and optional time windows.")
    ap.add_argument("--config", "-c", default="config.json", help="Path to config JSON.")
    ap.add_argument("--keyword", "-k", action="append", help="Keyword to search (can be provided multiple times).")
    ap.add_argument("--regex", "-r", action="append", help="Regex pattern to search (can be provided multiple times).")
    ap.add_argument("--any", dest="match_any", action="store_true", help="Match ANY of the patterns.")
    ap.add_argument("--all", dest="match_all", action="store_true", help="Match ALL of the patterns.")
    ap.add_argument("--since", help='Start time (local). Formats: "YYYY-MM-DD", "YYYY-MM-DD HH:MM[:SS]".')
    ap.add_argument("--until", help='End time (local). Formats: "YYYY-MM-DD", "YYYY-MM-DD HH:MM[:SS]".')
    ap.add_argument("--format", choices=["console", "csv", "jsonl"], help="Output format (overrides config).")
    ap.add_argument("--output", help="Output path for CSV/JSONL.")
    ap.add_argument("--encoding", help="File encoding (default utf-8).")
    ap.add_argument("--ignore-case", action="store_true", help="Case-insensitive search.")
    ap.add_argument("--include", action="append", help="Add include glob/file (can repeat).")
    ap.add_argument("--exclude", action="append", help="Add exclude glob/file (can repeat).")
    ap.add_argument("--follow", "-f", action="store_true", help="Follow the files for new lines (tail -f).")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    include = list(cfg.get("include", [])) + (args.include or [])
    exclude = list(cfg.get("exclude", [])) + (args.exclude or [])

    encoding = args.encoding or cfg.get("encoding", "utf-8")
    ignore_case = bool(args.ignore_case or cfg.get("ignore_case", False))
    keywords = (cfg.get("keywords") or [])
    regexes = (cfg.get("regexes") or [])
    if args.keyword:
        keywords.extend(args.keyword)
    if args.regex:
        regexes.extend(args.regex)
    match_mode = ("all" if args.match_all else "any" if args.match_any else cfg.get("match_mode", "any")).lower()

    ts_cfg = cfg.get("timestamp", {})
    ts_enabled = bool(ts_cfg.get("enabled", False))
    ts_regex = re.compile(ts_cfg.get("regex")) if (ts_enabled and ts_cfg.get("regex")) else None
    ts_fmt = ts_cfg.get("strftime") if ts_enabled else None
    assume_tz = ts_cfg.get("assume_tz", "UTC")

    since = parse_dt(args.since) if args.since else None
    until = parse_dt(args.until) if args.until else None

    out_cfg = cfg.get("output", {})
    out_format = args.format or out_cfg.get("format", "console")
    out_path = args.output or out_cfg.get("path")

    if out_format in ("csv", "jsonl") and not out_path:
        print("[INFO] No output path provided; writing to stdout.", file=sys.stderr)

    kw_patterns, rx_patterns = compile_patterns(keywords, regexes, ignore_case)

    # Field extraction regexes (named groups)
    field_cfgs = cfg.get("field_patterns", [])
    field_patterns = []
    if field_cfgs:
        flags = re.IGNORECASE if ignore_case else 0
        for entry in field_cfgs:
            if isinstance(entry, dict):
                pat = entry.get("regex")
            else:
                pat = str(entry)
            if not pat:
                continue
            try:
                field_patterns.append(re.compile(pat, flags))
            except re.error as e:
                print(f"[WARN] Bad field regex skipped: {pat} ({e})", file=sys.stderr)

    files = find_files(include, exclude)
    if not files:
        print("[WARN] No files matched your include patterns.", file=sys.stderr)
        sys.exit(1)

    # Prepare output
    out_fh = None
    csv_writer = None
    dynamic_fields = set()
    if out_format == "csv":
        out_fh = open(out_path, "w", newline="", encoding="utf-8") if out_path else sys.stdout
    elif out_format == "jsonl":
        out_fh = open(out_path, "w", encoding="utf-8") if out_path else sys.stdout

    total = 0
    matched = 0

    def emit_record(fpath, lineno, ts_out, reason, line, extra_fields):
        nonlocal csv_writer, dynamic_fields, matched
        matched += 1
        if out_format == "console":
            fields_str = " ".join([f"{k}={v}" for k,v in extra_fields.items()]) if extra_fields else ""
            print(f"{fpath}|{lineno}|{ts_out}|{reason}| {fields_str} {line}".rstrip())
        elif out_format == "csv":
            dynamic_fields |= set(extra_fields.keys())
            fieldnames = ["file", "lineno", "timestamp", "reason"] + sorted(dynamic_fields) + ["line"]
            if csv_writer is None:
                csv_writer = csv.DictWriter(out_fh, fieldnames=fieldnames)
                csv_writer.writeheader()
            row = {"file": str(fpath), "lineno": lineno, "timestamp": ts_out, "reason": reason or "", "line": line}
            row.update(extra_fields)
            csv_writer.writerow(row)
        elif out_format == "jsonl":
            rec = {"file": str(fpath), "lineno": lineno, "timestamp": ts_out, "reason": reason, "line": line}
            if extra_fields:
                rec.update(extra_fields)
            out_fh.write(json.dumps(rec, ensure_ascii=False) + "\\n")

    def process_line(fpath, lineno, line):
        ts = extract_timestamp(line, ts_regex, ts_fmt, assume_tz) if ts_enabled else None
        if not within_window(ts, since, until):
            return
        ok, reason = match_line(line, kw_patterns, rx_patterns, match_mode)
        if not ok:
            return
        extra = {}
        for ptn in field_patterns:
            m = ptn.search(line)
            if m:
                extra.update({k: v for k, v in m.groupdict().items() if k})
        ts_out = ts.isoformat() if ts else ""
        emit_record(fpath, lineno, reason=reason, ts_out=ts_out, line=line, extra_fields=extra)

    # Initial pass
    for f, lineno, line in iter_lines(files, encoding):
        total += 1
        process_line(f, lineno, line)

    # Follow mode
    if args.follow:
        print(f"[FOLLOW] Watching {len(files)} file(s). Press Ctrl+C to stop.", file=sys.stderr)
        try:
            def cb(fpath, lineno, line):
                process_line(fpath, lineno, line)
            _tail_files(files, encoding, cb, poll_interval=0.5)
        except KeyboardInterrupt:
            pass

    if out_fh and out_fh is not sys.stdout:
        out_fh.close()
    print(f"[DONE] Scanned {len(files)} file(s), {total} line(s). Matches: {matched}.", file=sys.stderr)

if __name__ == "__main__":
    main()
