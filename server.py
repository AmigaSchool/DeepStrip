#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server.py
---------
Thin entrypoint for running the DeepStrip API service.
All endpoints are defined in deepstrip_api.py.
"""

import uvicorn
from deepstrip_api import app

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",   # listen on all interfaces
        port=8080,        # default port for Render services
        reload=False       # set True only for local dev
    )
