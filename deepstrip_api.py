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
  /hexdump       - view file in chosen encoding
  /load          - load file from disk and return encoded
  /save          - save file to disk (decoded from encoding)
  /orcad/index   - classify OrCAD files
  /deploy        - trigger redeploy (stub or webhook)
"""

from pathlib import Path
from fastapi import FastAPI, Body
from typing import Dict, Any, List
import base64

# Import DeepStrip internals
from deepstrip_4430_beta19 import (
    ExtractionPipeline, Config,
    scan_unlinked_files, generate_manifest,
    HexDump, TokenEncoder, FormatDetector
)

app = FastAPI(
    title="DeepStrip API",
    version="v2.1",
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
    if not url:
        return {"status": "error", "message": "Missing URL"}

    try:
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
        "version": "v2.1",
        "python": "3.10+",
        "containers": [
            "zip","tar","gzip","bzip2","xz","7z","cab","arj",
            "lzh","arc","is3","iscab","cfbf","zoo","pak"
        ],
        "plugins": 0
    }

# -------------------------------------------------------------------
# Hexdump (standardized)
# -------------------------------------------------------------------
@app.post("/hexdump")
async def hexdump(payload: Dict[str, Any] = Body(...)):
    url = payload.get("url")
    mode = payload.get("mode", "hex")      # binary, hex, base64, tb256, braille
    spaced = payload.get("spaced", False) # add spacing between tokens
    if not url:
        return {"status": "error", "message": "Missing URL"}

    try:
        data = Path(url).read_bytes() if Path(url).exists() else b""

        if mode == "base64":
            encoded = base64.b64encode(data).decode()
        elif mode in ("tb256", "gemini"):
            out = TokenEncoder.encode(data, "gemini")
            encoded = " ".join(out) if spaced else out
        elif mode == "braille":
            out = TokenEncoder.encode(data, "braille")
            encoded = " ".join(out) if spaced else out
        elif mode == "hex" or mode == "binary":
            h = data.hex()
            encoded = " ".join(h[i:i+2] for i in range(0, len(h), 2)) if spaced else h
        else:
            encoded = HexDump.classic(data)

        return {"status": "ok", "mode": mode, "content": encoded}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------------
# Save file (decode from encoding)
# -------------------------------------------------------------------
@app.post("/save")
async def save(payload: Dict[str, Any] = Body(...)):
    filename = payload.get("filename", "out.bin")
    content = payload.get("content")
    mode = payload.get("mode", "binary")
    spaced = payload.get("spaced", False)

    if content is None:
        return {"status": "error", "message": "Missing content"}

    try:
        if mode in ("hex", "binary"):
            raw = bytes.fromhex(content.replace(" ", "")) if spaced else bytes.fromhex(content)
        elif mode == "base64":
            raw = base64.b64decode(content)
        elif mode in ("tb256", "gemini"):
            raw = TokenEncoder.decode(content.replace(" ", ""), "gemini")
        elif mode == "braille":
            raw = TokenEncoder.decode(content.replace(" ", ""), "braille")
        else:
            return {"status": "error", "message": f"Unsupported mode {mode}"}

        path = Path("./output") / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return {"status": "ok", "saved": str(path), "size": len(raw)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------------
# Load file (encode to chosen format)
# -------------------------------------------------------------------
@app.post("/load")
async def load(payload: Dict[str, Any] = Body(...)):
    filename = payload.get("filename")
    mode = payload.get("mode", "binary")
    spaced = payload.get("spaced", False)
    if not filename:
        return {"status": "error", "message": "Missing filename"}

    try:
        path = Path("./output") / filename
        data = path.read_bytes()

        if mode == "base64":
            encoded = base64.b64encode(data).decode()
        elif mode in ("tb256", "gemini"):
            out = TokenEncoder.encode(data, "gemini")
            encoded = " ".join(out) if spaced else out
        elif mode == "braille":
            out = TokenEncoder.encode(data, "braille")
            encoded = " ".join(out) if spaced else out
        elif mode in ("hex", "binary"):
            h = data.hex()
            encoded = " ".join(h[i:i+2] for i in range(0, len(h), 2)) if spaced else h
        else:
            encoded = HexDump.classic(data)

        return {"status": "ok", "filename": filename, "mode": mode, "content": encoded}
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
            classified.append({
                "file": f,
                "type": "unknown",
                "orcad_format": False,
                "notes": str(e)
            })
    return {"classified": classified}

# -------------------------------------------------------------------
# Deploy (stub or webhook integration)
# -------------------------------------------------------------------
@app.post("/deploy")
async def trigger_deploy():
    return {"status": "deploy triggered", "detail": "Triggered via API stub"}
