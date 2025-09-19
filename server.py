from fastapi import FastAPI, Body, HTTPException
from pydantic import BaseModel
from deepstrip_api import DeepStripAPI

app = FastAPI(
    title="DeepStrip Archive & OrCAD API",
    version="1.0.0",
    description="FastAPI wrapper around DeepStrip for GPT Actions"
)

ds_api = DeepStripAPI(output_dir="output")

# Input schema with validation
class ProcessPayload(BaseModel):
    url: str
    operation: str
    filters: str = None
    outputDir: str = "output"

class OrCadIndexPayload(BaseModel):
    files: list

@app.get("/ping")
def ping():
    """Health check endpoint."""
    return {"status": "ok", "message": "DeepStrip API is live"}

@app.post("/process")
def process_archive(payload: ProcessPayload):
    """Process archive from remote URL."""
    result = ds_api.process(
        url=payload.url,
        operation=payload.operation,
        filters=payload.filters,
        outdir=payload.outputDir
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result)
    return result

@app.post("/orcad/index")
def orcad_index(payload: OrCadIndexPayload):
    """Index file list for OrCAD classification."""
    files = payload.files
    if not isinstance(files, list) or not files:
        raise HTTPException(status_code=422, detail="Missing or invalid 'files'")
    results = []
    for f in files:
        results.append({
            "file": f,
            "type": "DSN" if f.lower().endswith(".dsn") else "OLB" if f.lower().endswith(".olb") else "other",
            "orcad_format": f.lower().endswith((".dsn", ".olb", ".sch", ".lib")),
            "header": {"version": "simulated"}
        })
    return {"classified": results}
