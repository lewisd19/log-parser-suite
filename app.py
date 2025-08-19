
import io, os, json, csv, zipfile, shutil, uuid, subprocess
from pathlib import Path
from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request
from typing import List

BASE = Path(__file__).parent
UPLOADS = BASE / "uploads"
RESULTS = BASE / "results"
TEMPLATES = Jinja2Templates(directory=str(BASE / "templates"))

app = FastAPI(title="Log Parser Web UI")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

LOGSEARCH = Path("/mnt/data/logsearch.py")  # existing parser

def _safe_list(text: str) -> List[str]:
    if not text:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]

def _write_config(workdir: Path, include_paths: List[str], keywords: List[str], regexes: List[str], match_mode: str, ignore_case: bool, out_format: str, results_jsonl: Path, results_csv: Path|None):
    cfg = {
      "include": include_paths,
      "exclude": ["**/archive/**", "**/.Trash/**"],
      "encoding": "utf-8",
      "ignore_case": ignore_case,
      "keywords": keywords,
      "regexes": regexes,
      "match_mode": match_mode,
      "timestamp": {
        "enabled": True,
        "regex": r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
        "strftime": "%Y-%m-%d %H:%M:%S.%f",
        "assume_tz": "local"
      },
      "field_patterns": [
        {
          "name": "haproxy_http_default",
          "regex": r"(?P<client_ip>\d{1,3}(?:\.\d{1,3}){3}):\d+\s+\[(?P<accept_date>[^\]]+)\]\s+(?P<frontend>\S+)\s+(?P<backend>\S+)/(?P<server>\S+)\s+(?P<Tq>\d+)/(?P<Tw>\d+)/(?P<Tc>\d+)/(?P<Tr>\d+)/(?P<Tt>\d+)\s+(?P<status>\d{3})\s+(?P<bytes>\d+)\s+(?P<captured_request_cookie>\S+)\s+(?P<captured_response_cookie>\S+)\s+(?P<termination_state>\S+)\s+(?P<actconn>\d+)/(?P<feconn>\d+)/(?P<beconn>\d+)/(?P<srvconn>\d+)/(?P<retries>\d+)\s+(?P<srv_queue>\d+)/(?P<backend_queue>\d+)\s+\"(?P<method>\S+)\s+(?P<path>[^\"]+)\s+(?P<http>HTTP/\d\.\d)\"\s+\"(?P<referrer>[^\"]*)\"\s+\"(?P<user_agent>[^\"]*)\""
        }
      ],
      "output": {
        "format": out_format,
        "path": str(results_csv if out_format == "csv" else results_jsonl)
      }
    }
    (workdir/"config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return workdir/"config.json"

def _extract_zip_to(tmpdir: Path, uploaded_zip: Path) -> List[str]:
    with zipfile.ZipFile(uploaded_zip, "r") as zf:
        zf.extractall(tmpdir)
    return [str(tmpdir / "**/*.log"), str(tmpdir / "**/*.out"), str(tmpdir / "**/*.gz"), str(tmpdir / "**/*.log.gz")]

@app.get("/", response_class=HTMLResponse)
def index(request: Request, message: str|None = None, ok: bool = True):
    return TEMPLATES.TemplateResponse("index.html", {"request": request, "message": message, "ok": ok})

@app.post("/upload", response_class=HTMLResponse)
async def upload(request: Request,
                 file: UploadFile,
                 format: str = Form("jsonl"),
                 keywords: str = Form(""),
                 regexes: str = Form(""),
                 match_mode: str = Form("any"),
                 ignore_case: str = Form("true")):
    wid = uuid.uuid4().hex
    workdir = RESULTS / wid
    workdir.mkdir(parents=True, exist_ok=True)
    upath = UPLOADS / f"{wid}_{file.filename}"
    upath.write_bytes(await file.read())

    include_paths: List[str] = []
    if upath.suffix.lower() == ".zip":
        include_paths = _extract_zip_to(workdir, upath)
    else:
        target = workdir / file.filename
        import shutil
        shutil.copy(upath, target)
        root = target.parent
        include_paths = [str(root / "**/*.log"), str(root / "**/*.out"), str(root / "**/*.gz"), str(root / "**/*.log.gz")]

    jsonl_out = workdir / "results.jsonl"
    csv_out = workdir / "results.csv" if format == "csv" else None

    cfg_path = _write_config(
        workdir=workdir,
        include_paths=include_paths,
        keywords=_safe_list(keywords),
        regexes=_safe_list(regexes),
        match_mode=match_mode,
        ignore_case=(ignore_case.lower() == "true"),
        out_format=format,
        results_jsonl=jsonl_out,
        results_csv=csv_out
    )

    cmd = ["python3", str(Path("/mnt/data/logsearch.py")), "--config", str(cfg_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    stderr = proc.stderr.strip()

    preview = []
    header = []
    if format == "jsonl":
        if jsonl_out.exists():
            with open(jsonl_out, "r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    if i >= 100: break
                    try:
                        obj = json.loads(line)
                        preview.append(obj)
                    except Exception:
                        continue
        if preview:
            keys = set()
            for row in preview:
                keys.update(row.keys())
            header = sorted(keys)
    else:
        if csv_out and csv_out.exists():
            import csv
            with open(csv_out, "r", encoding="utf-8") as f:
                r = csv.DictReader(f)
                header = r.fieldnames or []
                for i, row in enumerate(r):
                    if i >= 100: break
                    preview.append(row)

    jsonl_url = f"/download/{wid}/results.jsonl"
    csv_url = f"/download/{wid}/results.csv" if (csv_out and csv_out.exists()) else None

    return TEMPLATES.TemplateResponse("results.html", {
        "request": request,
        "jsonl_url": jsonl_url,
        "csv_url": csv_url,
        "preview": preview,
        "header": header
    })

@app.get("/download/{wid}/{fname}")
def download(wid: str, fname: str):
    path = RESULTS / wid / fname
    if not path.exists():
        return HTMLResponse("<p>File not found.</p>", status_code=404)
    return FileResponse(str(path), filename=fname)
