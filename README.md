# DeepStrip API Wrapper

This repo contains the DeepStrip API wrapper for FastAPI deployment.

- `deepstrip_api.py` → wrapper class around DeepStrip
- `server.py` → FastAPI server exposing `/process` and `/orcad/index`
- `requirements.txt` → dependencies for Render

## Deploy on Render
1. Push this repo to GitHub
2. On Render.com → New Web Service → connect this repo
3. Build command:
