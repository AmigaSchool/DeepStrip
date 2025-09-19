from pathlib import Path
import hashlib, requests
from deepstrip import Pipeline, Config, Logger
from urllib.error import URLError
from aiohttp.client_exceptions import ClientResponseError

class DeepStripAPI:
    def __init__(self, output_dir="output", verbose=0, quiet=False):
        cfg = Config(output_dir=output_dir, verbose=verbose, quiet=quiet)
        self.pipeline = Pipeline(cfg)
        self.logger = Logger(verbose=verbose)

    def process(self, url: str, operation: str, filters=None, outdir: str = "output"):
        # Validate input
        if not url or not isinstance(url, str) or not url.startswith("http"):
            return {"status": "error", "error": "Invalid or missing 'url'"}
        if not operation or not isinstance(operation, str):
            return {"status": "error", "error": "Missing or invalid 'operation'"}
        if filters and isinstance(filters, list):
            filters = ",".join(filters)

        try:
            if operation == "list":
                return self._list_files(url, filters)
            elif operation == "extract":
                return self._extract(url, outdir)
            elif operation == "analyze":
                return self._analyze(url)
            elif operation == "fetch":
                return {"status": "ok", "message": f"Fetched {url} (no extraction)"}
            else:
                return {"status": "error", "error": f"Unsupported operation: {operation}"}
        except (URLError, ClientResponseError) as e:
            return {
                "status": "error",
                "error": "Client response/network error",
                "detail": str(e),
                "url": url
            }
        except Exception as e:
            return {
                "status": "error",
                "error": "Unhandled server exception",
                "detail": str(e),
                "url": url
            }

    def _list_files(self, url: str, filters: str = None):
        try:
            files = self.pipeline.stream_extract(url, max_files=100)
            if filters:
                patterns = [f.strip().lower().replace("*", "") for f in filters.split(",")]
                files = [f for f in files if any(f[0].lower().endswith(p) for p in patterns)]
            return {"status": "ok", "files": [{"name": f[0], "size": len(f[1])} for f in files]}
        except Exception as e:
            return {
                "status": "error",
                "error": "list operation failed",
                "detail": str(e),
                "url": url
            }

    def _extract(self, url: str, outdir: str):
        try:
            self.pipeline.stream_extract(url)
            return {"status": "ok", "output": outdir}
        except Exception as e:
            return {
                "status": "error",
                "error": "extract failed",
                "detail": str(e),
                "url": url
            }

    def _analyze(self, url: str):
        try:
            r = requests.get(url, timeout=20)
            data = r.content
            entropy = 0.0
            if data:
                freq = {b: data.count(b) for b in set(data)}
                n = len(data)
                import math
                entropy = -sum((c/n)*math.log2(c/n) for c in freq.values())
            return {
                "status": "ok",
                "size": len(data),
                "entropy": round(entropy, 4),
                "hashes": {
                    "md5": hashlib.md5(data).hexdigest(),
                    "sha256": hashlib.sha256(data).hexdigest()
                }
            }
        except Exception as e:
            return {
                "status": "error",
                "error": "analyze failed",
                "detail": str(e),
                "url": url
            }
