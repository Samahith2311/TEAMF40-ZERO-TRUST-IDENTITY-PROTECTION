"""
Vercel FastAPI entrypoint.
Exposes the FastAPI instance from src.api.
"""
import os
import sys

root_dir = os.path.dirname(os.path.abspath(__file__))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from src.api import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
