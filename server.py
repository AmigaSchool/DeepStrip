from fastapi import FastAPI, Body, HTTPException
from pydantic import BaseModel
from deepstrip_api import DeepStripAPI
import requests

app = FastAPI(
    title="DeepStrip Archive & OrCAD API",
    version="v1.02",
    description="Universal archive extractor and OrCAD analyzer. Hosted on Render and deployed from GitHub."
)

# Initialize DeepStrip API wrapper
ds_api = DeepStripAPI(output_dir="output")

# === Schemas ===

class ProcessPayload(BaseModel):
    url: str
    operation: str
    filters: str | None = None
    outputDir: str = "output"

class OrCadIndexPayload(BaseModel):
    files: list[str]

# === Endpoints ===

@app.get("/ping")
def ping():
    """Health check endpoint"""
    return {"status": "ok", "message": "DeepStrip API is live"}

@app.post("/process")
def process_archive(payload: ProcessPayload):
    """Process archive from remote URL"""
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
    """Index file list for OrCAD classification"""
    if not isinstance(payload.files, list) or not payload.files:
        raise HTTPException(status_code=422, detail="Missing or invalid 'files'")
    results = []
    for f in payload.files:
        results.append({
            "file": f,
            "type": (
                "DSN" if f.lower().endswith(".dsn")
                else "OLB" if f.lower().endswith(".olb")
                else "SCH" if f.lower().endswith(".sch")
                else "LIB" if f.lower().endswith(".lib")
                else "other"
            ),
            "orcad_format": f.lower().endswith((".dsn", ".olb", ".sch", ".lib")),
            "header": {"version": "simulated"},
            "notes": ""
        })
    return {"classified": results}

@app.post("/deploy")
def trigger_deploy():
    """Trigger redeploy via Render Deploy Hook"""
    DEPLOY_HOOK = "https://api.render.com/deploy/srv-d36ev61r0fns73adqegg?key=f1a9-zop4hQ"
    try:
        r = requests.post(DEPLOY_HOOK, timeout=15)
        if r.status_code == 200:
            return {"status": "deploy triggered", "detail": r.text}
        else:
            raise HTTPException(status_code=500, detail=r.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
