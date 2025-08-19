# log-parser-suite

# Log Parser Suite (CLI + Web UI)

Cross-platform **Python log parser** with a configurable **FastAPI Web UI**.  
Search app/webserver logs by keywords/regex, filter by time window, auto-extract structured fields (Apache/Nginx/IIS/HAProxy), and export to CSV/JSONL.

## Features
- Works on **Windows & Linux** (macOS too).
- **Config-driven**: keywords, regexes, include/exclude globs, case sensitivity.
- **Field extraction** via named regex groups (e.g. HAProxy).
- **Follow mode** (`-f`) to tail files live (rotation-aware).
- Reads `.log` and `.gz` (follow mode skips `.gz`).
- **Web UI** for uploads: `.zip`, `.log`, `.gz` with preview + downloads.
- **Docker Compose** and **pipx/venv** instructions (JAMF-friendly).

---

## Quick Start — CLI

```bash
python3 logsearch.py -c config.json
# Time window (local)
python3 logsearch.py -c config.json --since "2025-08-01 00:00:00" --until "2025-08-19 23:59:59"
# Ad-hoc filters
python3 logsearch.py -c config.json -k ERROR -r "\b5\d{2}\b" --any
# Export
python3 logsearch.py -c config.json --format csv --output hits.csv
python3 logsearch.py -c config.json --format jsonl --output hits.jsonl
# Follow mode
python3 logsearch.py -c config.json -f
