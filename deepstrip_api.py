#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deepstrip_api.py - Dynamic version loader
Automatically finds and imports the latest deepstrip_*.py version
"""
from pathlib import Path
from typing import Dict, Any, List
import base64
import importlib.util
import sys

# ============================================================================
# DYNAMIC DEEPSTRIP VERSION LOADER
# ============================================================================

def load_latest_deepstrip():
    """Find and import the latest deepstrip_*.py file"""
    deepstrip_files = sorted(
        Path(".").glob("deepstrip_*.py"),
        reverse=True  # Gets highest version number first
    )
    
    if not deepstrip_files:
        raise ImportError("No deepstrip_*.py file found in directory")
    
    latest_file = deepstrip_files[0]
    module_name = latest_file.stem
    
    # Load module dynamically
    spec = importlib.util.spec_from_file_location(module_name, latest_file)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {latest_file}")
    
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    
    return module, module_name

# Load the module
try:
    deepstrip_module, version_name = load_latest_deepstrip()
    
    # Import required classes/functions
    ExtractionPipeline = deepstrip_module.ExtractionPipeline
    Config = deepstrip_module.Config
    HexDump = getattr(deepstrip_module, 'HexDump', None)
    TokenEncoder = getattr(deepstrip_module, 'TokenEncoder', None)
    FormatDetector = getattr(deepstrip_module, 'FormatDetector', None)
    scan_unlinked_files = getattr(deepstrip_module, 'scan_unlinked_files', None)
    generate_manifest = getattr(deepstrip_module, 'generate_manifest', None)
    
    print(f"✓ Loaded DeepStrip module: {version_name}")
    
except Exception as e:
    print(f"✗ Failed to load DeepStrip: {e}")
    # Fallback stubs
    class ExtractionPipeline:
        def __init__(self, config): pass
        def extract(self, data, output): return []
        def stream_extract(self, url, max_files): return []
        def analyze_file(self, data): return {}
    
    class Config:
        def __init__(self): pass
    
    class HexDumpStub:
        @staticmethod
        def classic(data): return data.hex()
    
    class TokenEncoderStub:
        @staticmethod
        def encode(data, mode): return data.hex()
        @staticmethod
        def decode(text, mode): return bytes.fromhex(text)
    
    class FormatDetectorStub:
        @staticmethod
        def detect(data): return "unknown"
    
    HexDump = HexDumpStub
    TokenEncoder = TokenEncoderStub
    FormatDetector = FormatDetectorStub
    scan_unlinked_files = lambda url: []
    generate_manifest = lambda url, results: ""
    version_name = "FALLBACK"

# ============================================================================
# API HANDLERS
# ============================================================================

def handle_process(file_contents: bytes, filename: str) -> dict:
    """Process uploaded archive file"""
    try:
        pipeline = ExtractionPipeline(Config())
        files = pipeline.extract(file_contents, Path("./output"))
        return {
            "status": "success",
            "filename": filename,
            "size": len(file_contents),
            "extracted_files": [
                {"name": str(f[0]), "size": len(f[1])} for f in files
            ]
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

def handle_extract(payload: Dict[str, Any]) -> dict:
    """Extract archive from URL or path"""
    url = payload.get("url")
    if not url:
        return {"status": "error", "message": "Missing URL"}
    
    try:
        path = Path(url)
        data = path.read_bytes() if path.exists() else b""
        pipeline = ExtractionPipeline(Config())
        files = pipeline.extract(data, Path("./output"))
        return {
            "status": "ok",
            "files": [{"name": str(f[0]), "size": len(f[1])} for f in files]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def handle_stream(payload: Dict[str, Any]) -> dict:
    """Stream-extract from remote URL"""
    url = payload.get("url")
    max_files = payload.get("maxFiles")
    if not url:
        return {"status": "error", "message": "Missing URL"}
    
    try:
        pipeline = ExtractionPipeline(Config())
        files = pipeline.stream_extract(url, max_files)
        return {
            "status": "ok",
            "files": [{"name": str(f[0]), "size": len(f[1])} for f in files]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def handle_analyze(payload: Dict[str, Any]) -> dict:
    """Analyze a file or archive"""
    url = payload.get("url")
    if not url:
        return {"status": "error", "message": "Missing URL"}
    
    try:
        path = Path(url)
        data = path.read_bytes() if path.exists() else b""
        pipeline = ExtractionPipeline(Config())
        result = pipeline.analyze_file(data)
        return {"status": "ok", **result}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def handle_scan_unlinked(payload: Dict[str, Any]) -> dict:
    """Scan Internet Archive for unlinked files"""
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

def get_info() -> dict:
    """Return API info"""
    return {
        "version": version_name,
        "python": "3.10+",
        "containers": [
            "zip","tar","gzip","bzip2","xz","7z","cab","arj",
            "lzh","arc","is3","iscab","cfbf","zoo","pak"
        ],
        "plugins": 0
    }

def handle_hexdump(payload: Dict[str, Any]) -> dict:
    """Generate hexdump in various formats"""
    url = payload.get("url")
    mode = payload.get("mode", "hex")
    spaced = payload.get("spaced", False)
    
    if not url:
        return {"status": "error", "message": "Missing URL"}
    
    try:
        path = Path(url)
        data = path.read_bytes() if path.exists() else b""
        
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

def handle_save(payload: Dict[str, Any]) -> dict:
    """Save file (decode from encoding)"""
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

def handle_load(payload: Dict[str, Any]) -> dict:
    """Load file (encode to chosen format)"""
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

def handle_orcad_index(file_contents: bytes, filename: str) -> dict:
    """Classify OrCAD file type (for upload handler)"""
    try:
        fmt = FormatDetector.detect(file_contents)
        return {
            "file": filename,
            "type": fmt,
            "orcad_format": fmt in ("dsn", "sch", "olb", "lib"),
            "notes": "detected by FormatDetector"
        }
    except Exception as e:
        return {
            "file": filename,
            "type": "unknown",
            "orcad_format": False,
            "notes": str(e)
        }

def handle_orcad_index_batch(payload: Dict[str, Any]) -> dict:
    """Classify OrCAD files from paths (for JSON payload)"""
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

def handle_deploy() -> dict:
    """Deploy stub"""
    return {"status": "deploy triggered", "detail": "Triggered via API stub"}
