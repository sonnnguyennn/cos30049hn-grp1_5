import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "db" / "traffic.db"


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH, timeout=10)) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                event TEXT NOT NULL,
                message TEXT NOT NULL,
                filename TEXT
            )
        """)
        db.commit()


def write_log(event: str, message: str, filename: str | None = None) -> None:
    with closing(sqlite3.connect(DB_PATH, timeout=10)) as db:
        db.execute(
            "INSERT INTO logs (event, message, filename) VALUES (?, ?, ?)",
            (event, message, filename),
        )
        db.commit()


def read_logs(limit: int = 50) -> list[dict[str, object]]:
    with closing(sqlite3.connect(DB_PATH, timeout=10)) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT id, created_at, event, message, filename "
            "FROM logs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]