"""Secure demo application for testing BARBAROSSA."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware import Middleware
import sqlite3
from pathlib import Path
from typing import Optional

app = FastAPI(
    title="Secure Demo App",
    docs_url=None,
    redoc_url=None,
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.example.com"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Database setup
DB_PATH = Path(__file__).parent / "app.db"


def init_db() -> None:
    """Initialize database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


@app.get("/health")
def health_check() -> dict:
    """Health check endpoint (public safe endpoint)."""
    return {"status": "healthy"}


@app.get("/api/user/{user_id}")
def get_user(user_id: int) -> dict:
    """Get user info with proper validation and no data exposure."""
    if user_id < 1:
        raise HTTPException(status_code=400, detail="Invalid user ID")
    
    return {
        "id": user_id,
        "status": "found"
    }


@app.post("/api/search")
def search(query: str = "") -> dict:
    """Search with parameterized queries."""
    if len(query) > 100:
        raise HTTPException(status_code=400, detail="Query too long")
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    # Parameterized query - safe from SQL injection
    c.execute("SELECT id FROM users WHERE username LIKE ?", (f"%{query}%",))
    results = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return {"results": results}


@app.api_route("/robots.txt", methods=["GET"])
def robots_txt() -> str:
    """Standard robots.txt."""
    return "User-agent: *\nDisallow: /admin\nDisallow: /internal"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8001,
        ssl_keyfile=None,
        ssl_certfile=None,
    )
