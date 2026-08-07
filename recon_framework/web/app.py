"""
Recon Framework — Web UI API Backend.
Flask app with SSE (Server-Sent Events) for live scan progress.
"""
import asyncio
import json
import os
import re
import sys
import uuid
import threading
import time
import logging
from datetime import datetime
from pathlib import Path

# Force UTF-8 for Windows console/file encoding (emoji safety)
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from flask import Flask, render_template, request, jsonify, Response, send_from_directory

from ..config import ScanConfig
from ..orchestrator import Orchestrator, PASSIVE_MODULES, ACTIVE_MODULES, ALL_MODULES

app = Flask(__name__, static_folder="static", template_folder="templates")

# ── State ────────────────────────────────────────────────────────
scans: dict[str, dict] = {}   # scan_id -> {status, target, mode, findings, ...}
scan_logs: dict[str, list] = {}  # scan_id -> [log lines]

OUTPUT_ROOT = os.environ.get("RECON_OUTPUT_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "recon-output"))


def _run_scan(scan_id: str, target: str, mode: str, modules: list[str] | None, threads: int):
    """Run a scan in a background thread."""
    scan = scans[scan_id]
    scan["status"] = "running"
    scan["started_at"] = datetime.utcnow().isoformat()
    _log(scan_id, f"Starting {mode} scan against {target}")

    try:
        config = ScanConfig(
            target=target,
            mode=mode,
            output_dir=os.path.join(OUTPUT_ROOT, scan_id),
            threads=threads,
            rate_limit=0.3,
            verbose=False,
            modules=modules or [],
        )

        # Patch the orchestrator to emit logs into our scan_logs
        import recon_framework.utils.logger as log_mod
        _orig_print = log_mod.print_module_start
        _orig_finding = log_mod.print_finding

        def patched_print_module_start(name, tgt):
            _log(scan_id, f"▸ {name} → {tgt}")

        def patched_print_finding(severity, title, detail=""):
            _log(scan_id, f"  [{severity.upper()}] {title}")
            if detail:
                _log(scan_id, f"    {detail[:120]}")

        log_mod.print_module_start = patched_print_module_start
        log_mod.print_finding = patched_print_finding

        loop = asyncio.new_event_loop()
        orchestrator = Orchestrator(config)
        loop.run_until_complete(orchestrator.run())

        # Restore originals
        log_mod.print_module_start = _orig_print
        log_mod.print_finding = _orig_finding

        # Collect results
        scan["status"] = "completed"
        scan["completed_at"] = datetime.utcnow().isoformat()
        scan["findings"] = orchestrator.results.get("findings", [])
        scan["modules_run"] = orchestrator.results.get("modules_run", [])
        scan["output_dir"] = config.output_dir

        # Read generated reports
        md_path = os.path.join(config.output_dir, "report.md")
        json_path = os.path.join(config.output_dir, "report.json")
        if os.path.exists(md_path):
            with open(md_path) as f:
                scan["report_md"] = f.read()
        if os.path.exists(json_path):
            with open(json_path) as f:
                scan["report_json"] = json.load(f)

        _log(scan_id, f"✅ Scan completed — {len(scan['findings'])} findings")

    except Exception as e:
        scan["status"] = "error"
        scan["error"] = str(e)
        _log(scan_id, f"❌ Error: {e}")
        logging.getLogger("recon.web").exception("Scan failed")


def _log(scan_id: str, msg: str):
    """Append a log line to a scan."""
    ts = datetime.utcnow().strftime("%H:%M:%S")
    # Strip emoji characters that crash Windows charmap codec
    safe_msg = re.sub(
        r'[\U0001F000-\U0001FFFF\u2600-\u27BF\u2B50\u2705\u274C\u2714\u2716\u23F0\u23F3'
        r'\U0001f534\U0001f7e0\U0001f7e1\U0001f7e2\U0001f535\u26aa\u26ab]',
        '', msg
    ).strip()
    line = f"[{ts}] {safe_msg}"
    scan_logs.setdefault(scan_id, []).append(line)
    # Keep last 500 lines
    if len(scan_logs[scan_id]) > 500:
        scan_logs[scan_id] = scan_logs[scan_id][-500:]


# ── Routes ───────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/modules", methods=["GET"])
def get_modules():
    """Return available modules grouped by type."""
    passive = {name: cls.description for name, cls in PASSIVE_MODULES.items()}
    active = {name: cls.description for name, cls in ACTIVE_MODULES.items()}
    other = {name: cls.description for name, cls in ALL_MODULES.items()
             if name not in PASSIVE_MODULES and name not in ACTIVE_MODULES}
    return jsonify({"passive": passive, "active": active, "analysis": other})


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a new scan."""
    data = request.json or {}
    target = data.get("target", "").strip()
    mode = data.get("mode", "hybrid")
    modules = data.get("modules")  # None = all
    threads = data.get("threads", 10)

    if not target:
        return jsonify({"error": "target is required"}), 400

    # Normalize
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    scan_id = uuid.uuid4().hex[:12]
    scans[scan_id] = {
        "id": scan_id,
        "target": domain,
        "target_url": target,
        "mode": mode,
        "status": "queued",
        "findings": [],
        "modules_run": [],
        "created_at": datetime.utcnow().isoformat(),
    }
    scan_logs[scan_id] = []

    thread = threading.Thread(target=_run_scan, args=(scan_id, domain, mode, modules, threads), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "queued"})


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    """Get scan status and results."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify(scan)


@app.route("/api/scan/<scan_id>/logs", methods=["GET"])
def get_scan_logs(scan_id):
    """Get scan log lines (supports ?since=N for incremental)."""
    if scan_id not in scan_logs:
        return jsonify({"error": "not found"}), 404
    since = request.args.get("since", 0, type=int)
    logs = scan_logs.get(scan_id, [])
    return jsonify({"logs": logs[since:], "total": len(logs)})


@app.route("/api/scan/<scan_id>/stream")
def stream_scan(scan_id):
    """SSE endpoint for live log streaming."""
    def generate():
        last_idx = 0
        while True:
            logs = scan_logs.get(scan_id, [])
            scan = scans.get(scan_id, {})
            if last_idx < len(logs):
                for line in logs[last_idx:]:
                    yield f"data: {json.dumps({'type': 'log', 'message': line})}\n\n"
                last_idx = len(logs)
            if scan.get("status") in ("completed", "error"):
                yield f"data: {json.dumps({'type': 'done', 'status': scan['status'], 'findings_count': len(scan.get('findings', []))})}\n\n"
                break
            yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
            time.sleep(1)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/scan/<scan_id>/report", methods=["GET"])
def get_report(scan_id):
    """Get the markdown report."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    fmt = request.args.get("format", "markdown")
    if fmt == "json":
        return jsonify(scan.get("report_json", {}))
    return scan.get("report_md", "No report generated yet."), 200, {"Content-Type": "text/markdown"}


@app.route("/api/scan/<scan_id>/download/<fmt>", methods=["GET"])
def download_report(scan_id, fmt):
    """Download report file."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    output_dir = scan.get("output_dir", "")
    if fmt == "md":
        path = os.path.join(output_dir, "report.md")
        if os.path.exists(path):
            return send_from_directory(os.path.dirname(path), os.path.basename(path),
                                       as_attachment=True, download_name=f"recon-{scan_id}.md")
    elif fmt == "json":
        path = os.path.join(output_dir, "report.json")
        if os.path.exists(path):
            return send_from_directory(os.path.dirname(path), os.path.basename(path),
                                       as_attachment=True, download_name=f"recon-{scan_id}.json")
    return jsonify({"error": "report not found"}), 404


@app.route("/api/scans", methods=["GET"])
def list_scans():
    """List all scans."""
    result = []
    for sid, scan in sorted(scans.items(), key=lambda x: x[1].get("created_at", ""), reverse=True):
        result.append({
            "id": scan["id"],
            "target": scan["target"],
            "mode": scan["mode"],
            "status": scan["status"],
            "findings_count": len(scan.get("findings", [])),
            "created_at": scan.get("created_at"),
            "completed_at": scan.get("completed_at"),
        })
    return jsonify(result)


def create_app():
    """Application factory."""
    os.makedirs(OUTPUT_ROOT, exist_ok=True)
    return app
