# =============================================================================
# run.py — Development / production entry point
# =============================================================================

import os
import sys

# Ensure the project root is always on the path regardless of where
# Python is invoked from (fixes ModuleNotFoundError: No module named 'app')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
    )
