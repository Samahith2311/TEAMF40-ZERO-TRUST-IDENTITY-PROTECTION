"""
Vercel FastAPI entrypoint.
Exposes the FastAPI instance from src.api.
"""
from src.api import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

