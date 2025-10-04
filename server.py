#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from fastapi import FastAPI, UploadFile, File, Body
from fastapi.responses import JSONResponse
from typing import Dict, Any, List
import deepstrip_api

app = FastAPI(
    title="DeepStrip API",
    description="FastAPI wrapper for DeepStrip archive extractor and OrCAD indexer",
    version="4.4.30"
)

@app.get("/healthz")
@app.get("/ping")
def health():
    return {"status": "ok", "message": "DeepStrip API is live"}

@app.get("/info")
async def info():
    return deepstrip_api.get_info()

@app.post("/process")
async def process_file(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        result = deepstrip_api.handle_process(contents, file.filename)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/extract")
async def extract(payload: Dict[str, Any] = Body(...)):
    try:
        result = deepstrip_api.handle_extract(payload)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/stream")
async def stream(payload: Dict[str, Any] = Body(...)):
    try:
        result = deepstrip_api.handle_stream(payload)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/analyze")
async def analyze(payload: Dict[str, Any] = Body(...)):
    try:
        result = deepstrip_api.handle_analyze(payload)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/scan-unlinked")
async def scan_unlinked(payload: Dict[str, Any] = Body(...)):
    try:
        result = deepstrip_api.handle_scan_unlinked(payload)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/hexdump")
async def hexdump(payload: Dict[str, Any] = Body(...)):
    try:
        result = deepstrip_api.handle_hexdump(payload)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/save")
async def save(payload: Dict[str, Any] = Body(...)):
    try:
        result = deepstrip_api.handle_save(payload)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/load")
async def load(payload: Dict[str, Any] = Body(...)):
    try:
        result = deepstrip_api.handle_load(payload)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/orcad/index")
async def orcad_index(files: List[UploadFile]):
    try:
        results = []
        for f in files:
            blob = await f.read()
            results.append(deepstrip_api.handle_orcad_index(blob, f.filename))
        return JSONResponse(content={"classified": results})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.post("/deploy")
async def trigger_deploy():
    return deepstrip_api.handle_deploy()
