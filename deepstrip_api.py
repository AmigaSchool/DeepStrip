from pathlib import Path
import hashlib, requests
from deepstrip import Pipeline, Config, Logger  # Import your DeepStrip core

class DeepStripAPI:
    def __init__(self, output_dir="output", verbose=0, quiet=False):
        cfg = Config(output_dir=output_dir, verbose=verbose, quiet=quiet)
        self.pipeline = Pipeline(cfg)
        self.logger = Logger(verbose=verbose, quiet=quiet)

    def process(self, url: str, operation: str, filters: str = None, outdir: str = "output"):
        if operation == "list":
            return self._list_files(url, filters)
        elif operation == "extract":
            return self._extract(url, outdir)
        elif operation == "analyze":
            return self._analyze(url)
        elif operation == "fetch":
            return {"status": "ok", "message": f"Fetched {url} (no extraction)"}
        else:
            return {"error": f"Unsupported operation: {operation}"}

    def _list_files(self, url: str, filters: str = None):
        # Placeholder – in production, integrate VirtualURLStream
        files = [
            {"name": "DISK1/ORCAD42.EXE", "size": 345678},
            {"name": "DISK1/LIBS/CAPSYM.OLB", "size": 45678, "orcad_format": True},
            {"name": "DISK1/DESIGN1.DSN", "size": 128934, "orcad_format": True}
        ]
        if filters:
            patterns = [f.strip().lower().replace("*", "") for f in filters.split(",")]
            files = [f for f in files if any(f["name"].lower().endswith(p) for p in patterns)]
        return {"status": "ok", "files": files}

    def _extract(self, url: str, outdir: str):
        ok = self.pipeline.extract(url, outdir)
        return {"status": "ok" if ok else "fail", "output": outdir}

    def _analyze(self, url: str):
        r = requests.get(url)
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
