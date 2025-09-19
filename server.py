from fastapi import FastAPI, Body
from deepstrip_api import DeepStripAPI

app = FastAPI(
    title="DeepStrip Archive & OrCAD API",
    version="1.0.0",
    description="DeepStrip backend for CustomGPT Actions"
)

ds_api = DeepStripAPI(output_dir="output")

@app.post("/process")
def process_archive(payload: dict = Body(...)):
    return ds_api.process(
        payload.get("url"),
        payload.get("operation"),
        payload.get("filters"),
        payload.get("outputDir", "output")
    )

@app.post("/orcad/index")
def orcad_index(payload: dict = Body(...)):
    files = payload.get("files", [])
    results = []
    for f in files:
        results.append({
            "file": f,
            "type": "DSN" if f.lower().endswith(".dsn") else "OLB" if f.lower().endswith(".olb") else "other",
            "orcad_format": f.lower().endswith((".dsn", ".olb", ".sch", ".lib")),
            "header": {"version": "simulated"}
        })
    return {"classified": results}
