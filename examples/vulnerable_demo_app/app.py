"""Vulnerable demo application for testing BARBAROSSA."""

import sqlite3
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(
    title="Vulnerable Demo App",
    docs_url="/docs",
    redoc_url="/redoc",
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
            username TEXT,
            password TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123')")
    conn.commit()
    conn.close()


init_db()


@app.get("/health")
def health_check() -> dict:
    """Container health endpoint for the isolated demo environment."""
    return {"status": "healthy"}


@app.get("/")
def read_root() -> HTMLResponse:
    """Root endpoint with visible debug info."""
    debug_info = f"""
    <html>
    <head>
        <title>Vulnerable Demo</title>
        <script>console.log('Debug mode enabled');</script>
    </head>
    <body>
        <h1>Vulnerable Demo App</h1>
        <p>This app intentionally has security issues for testing.</p>
        <hr>
        <h2>Debug Information</h2>
        <pre>
DATABASE: {DB_PATH}
DEBUG: true
SECRET_KEY: very-secret-123
API_KEY: sk_test_abcd1234efgh5678
        </pre>
    </body>
    </html>
    """
    return HTMLResponse(content=debug_info)


@app.get("/search")
def search(query: str = "") -> dict:
    """Unsafe search endpoint vulnerable to SQL injection indicators."""
    # Intentionally unsafe SQL construction for demonstration
    sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(sql)
        results = [dict(row) for row in c.fetchall()]
        conn.close()
        return {"results": results}
    except Exception as e:
        return {"error": str(e)}


@app.get("/user/{user_id}")
def get_user(user_id: str) -> dict:
    """Endpoint that echoes user input without sanitization."""
    return {"user_id": user_id, "message": f"User {user_id} profile"}


@app.post("/login")
def login(username: str, password: str) -> dict:
    """Login endpoint with weak checks."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        return {
            "status": "success",
            "message": f"Welcome {username}",
            "token": f"token_{username}_{password}",
        }
    return {"status": "failed"}


@app.get("/config")
def get_config() -> dict:
    """Exposed configuration endpoint."""
    return {
        "database_url": "postgresql://admin:password@localhost/app_db",
        "api_key": "sk_live_abc123def456",
        "debug": True,
        "secret_key": "my-secret-key",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104 - container listener
