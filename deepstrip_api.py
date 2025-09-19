#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deepstrip_api.py
----------------
FastAPI wrapper exposing DeepStrip features as a web service.
Aligned with REPL/CLI commands so CustomGPT Actions can call them directly.

Endpoints:
  /ping          - health check
  /extract       - extract an archive
  /stream        - stream-extract from remote URL
  /analyze       - analyze file/archive
  /scan-unlinked - scan Internet Archive for unlinked files
  /info          - system info
  /hexdump       - generate hexdump
  /orcad/index   - classify OrCAD files
  /deploy        - trigger redeploy (stub or webhook)
"""

from pathlib import Path
from fastapi import FastAPI, Body
from typing import Dict, Any, List

# Import DeepStrip internals
from deepstrip_4430_beta19 import (
    ExtractionPipeline, Config,
    scan_unlinked_files, generate_manifest,
    HexDump, FormatDetector
)

app = FastAPI(
    title="DeepStrip API",
    version="v2.0",
    description="Universal archive extractor and OrCAD analyzer. Hosted on Render."
)

# -------------------------------------------------------------------
# Health check
# -------------------------------------------------------------------
@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "DeepStrip API is live"}

# -------------------------------------------------------------------
# Extract archive (local or remote placeholder)
# -------------------------------------------------------------------
@app.post("/extract")
async def extract(payload: Dict[str, Any] = Body(...)):
    url = payload.get("url")
    filters = payload.get("filters")
    if not url:
        return {"status": "error", "message": "Missing URL"}

    try:
        # TODO: fetch from remote if needed. For now, assume local path.
        data = Path(url).read_bytes() if Path(url).exists() else b""
        pipeline = ExtractionPipeline(Config())
        files = pipeline.extract(data, Path("./output"))
        return {
            "status": "ok",
            "files": [{"name": f[0], "size": len(f[1])} for f in files]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------------
# Stream-extract from remote URL
# -------------------------------------------------------------------
@app.post("/stream")
async def stream(payload: Dict[str, Any] = Body(...)):
    url = payload.get("url")
    max_files = payload.get("maxFiles")
    if not url:
        return {"status": "error", "message": "Missing URL"}

    try:
        pipeline = ExtractionPipeline(Config())
        files = pipeline.stream_extract(url, max_files)
        return {
            "status": "ok",
            "files": [{"name": f[0], "size": len(f[1])} for f in files]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------------
# Analyze a file or archive
# -------------------------------------------------------------------
@app.post("/analyze")
async def analyze(payload: Dict[str, Any] = Body(...)):
    url = payload.get("url")
    if not url:
        return {"status": "error", "message": "Missing URL"}

    try:
        data = Path(url).read_bytes() if Path(url).exists() else b""
        pipeline = ExtractionPipeline(Config())
        result = pipeline.analyze_file(data)
        return {"status": "ok", **result}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------------
# Scan Internet Archive for unlinked files
# -------------------------------------------------------------------
@app.post("/scan-unlinked")
async def scan_unlinked(payload: Dict[str, Any] = Body(...)):
    base_url = payload.get("baseUrl")
    max_files = payload.get("maxFiles")
    if not base_url:
        return {"status": "error", "message": "Missing baseUrl"}

    try:
        results = scan_unlinked_files(base_url)
        if max_files:
            results = results[:max_files]
        manifest = generate_manifest(base_url, results)
        return {
            "status": "ok",
            "totalFound": len(results),
            "manifest": manifest,
            "files": [
                {"name": r[0], "url": r[1], "sha256": r[2]} for r in results
            ]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------------
# Info
# -------------------------------------------------------------------
@app.get("/info")
async def info():
    return {
        "version": "v2.0",
        "python": "3.10+",
        "containers": [
            "zip","tar","gzip","bzip2","xz","7z","cab","arj",
            "lzh","arc","is3","iscab","cfbf","zoo","pak"
        ],
        "plugins": 0
    }

# -------------------------------------------------------------------
# Hexdump
# -------------------------------------------------------------------
@app.post("/hexdump")
async def hexdump(payload: Dict[str, Any] = Body(...)):
    url = payload.get("url")
    fmt = payload.get("format", "classic")
    if not url:
        return {"status": "error", "message": "Missing URL"}

    try:
        data = Path(url).read_bytes() if Path(url).exists() else b""
        if fmt in ("tb256", "gemini"):
            dump = HexDump.tb256(data)
        elif fmt == "braille":
            dump = HexDump.tb256(data, "braille")
        elif fmt == "mixed":
            dump = HexDump.mixed(data)
        else:
            dump = HexDump.classic(data)
        return {"status": "ok", "hexdump": dump}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------------
# OrCAD Classification
# -------------------------------------------------------------------
@app.post("/orcad/index")
async def orcad_index(payload: Dict[str, Any] = Body(...)):
    files: List[str] = payload.get("files", [])
    if not files:
        return {"classified": []}
    classified = []
    for f in files:
        try:
            data = Path(f).read_bytes()
            fmt = FormatDetector.detect(data)
            classified.append({
                "file": f,
                "type": fmt,
                "orcad_format": fmt in ("dsn", "sch", "olb", "lib"),
                "notes": "detected by FormatDetector"
            })
        except Exception as e:
            classified.append({"file": f, "type": "unknown", "orcad_format": False, "notes": str(e)})
    return {"classified": classified}

# -------------------------------------------------------------------
# Deploy (stub or webhook integration)
# -------------------------------------------------------------------
@app.post("/deploy")
async def trigger_deploy():
    return {"status": "deploy triggered", "detail": "Triggered via API stub"}
