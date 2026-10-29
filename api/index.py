"""
Vercel serverless function entrypoint for FastAPI.
"""
import os
import sys
import traceback

# Ensure repository root is on sys.path so 'src' can be imported anywhere
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from src.api import app
except Exception as exc:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    app = FastAPI(title="Zero Trust API Fallback")
    _err_msg = str(exc)
    _err_tb = traceback.format_exc()

    @app.api_route("/{path_name:path}", methods=["GET", "POST", "OPTIONS"])
    async def fallback_handler(path_name: str):
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Backend initialization failed",
                "detail": _err_msg,
                "traceback": _err_tb,
            },
        )
