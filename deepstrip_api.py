#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DeepStrip API
-------------
FastAPI wrapper exposing DeepStrip features as a web service.
Aligned with REPL/CLI commands (extract, stream, analyze, scan-unlinked, etc.)
so CustomGPT Actions can call them 1-to-1.
"""

import hashlib
from pathlib import Path
from fastapi import FastAPI, Body
from typing import Optional, List, Dict, Any

# Import DeepStrip internals
from deepstrip_4430_beta19 import (
    ExtractionPipeline, Config,
    scan_unlinked_files, generate_manifest,
    HexDump, FormatDetector
)

app = FastAPI(title="DeepStrip API", version="v2.0")

# -------------------------------------------------------------------
# Basic Health
# -------------------------------------------------------------------
@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "DeepStrip API is live"}

# -------------------------------------------------------------------
# Extract archive
# -------------------------------------------------------------------
@app.post("/extract")
async def extract(payload: Dict[str, Any] = Body(...)):
    url = payload.get("url")
    filters = payload.get("filters")
    if not url:
        return {"status": "error", "message": "Missing URL"}

    try:
        pipeline = ExtractionPipeline(Config())
        files = pipeline.extract(
            data=Path(url).read_bytes() if Path(url).exists() else b"",  # TODO: fetch remote if needed
            output_dir=Path("./output")
        )
        return {
            "status": "ok",
            "files": [{"name": f[0], "size": len(f[1])} for f in files]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------------
# Stream archive
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
# Analyze file/archive
# -------------------------------------------------------------------
@app.post("/analyze")
async def analyze(payload: Dict[str, Any] = Body(...)):
    url = payload.get("url")
    if not url:
        return {"status": "error", "message": "Missing URL"}

    try:
        data = Path(url).read_bytes() if Path(url).exists() else b""  # TODO: fetch remote
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
        "containers": ["zip","tar","gzip","bzip2","xz","7z","cab","arj","lzh","arc","is3","iscab","cfbf","zoo","pak"],
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
        data = Path(url).read_bytes() if Path(url).exists() else b""  # TODO: fetch remote
        if fmt == "tb256" or fmt == "gemini":
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
# OrCAD Classification (kept as-is)
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
# Deploy (stub, you may wire into Render webhook)
# -------------------------------------------------------------------
@app.post("/deploy")
async def trigger_deploy():
    return {"status": "deploy triggered", "detail": "Triggered via API stub"}
