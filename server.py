#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse
import deepstrip_api

app = FastAPI(
    title="DeepStrip API",
    description="FastAPI wrapper for DeepStrip archive extractor and OrCAD indexer",
    version="4.4.30"
)

# -------------------------------------------------------------------
# Health check (Render will call this at /healthz)
# -------------------------------------------------------------------
@app.get("/healthz")
def health():
    return {"status": "ok"}

# -------------------------------------------------------------------
# Process endpoint - upload file, extract, and analyze
# -------------------------------------------------------------------
@app.post("/process")
async def process_file(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        result = deepstrip_api.handle_process(contents, file.filename)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

# -------------------------------------------------------------------
# OrCAD index endpoint - classify multiple files
# -------------------------------------------------------------------
@app.post("/orcad/index")
async def orcad_index(files: list[UploadFile]):
    try:
        results = []
        for f in files:
            blob = await f.read()
            results.append(deepstrip_api.handle_orcad_index(blob, f.filename))
        return JSONResponse(content={"classified": results})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
