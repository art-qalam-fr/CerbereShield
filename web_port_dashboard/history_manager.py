import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

class HistoryManager:
    """Gère l'historisation des snapshots et des alertes via SQLite."""

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            # Utilisation d'un chemin cohérent avec le serveur MCP si possible,
            # sinon stockage local dans le dossier state.
            import cerbere_paths as _paths
            db_path = _paths.state_dir() / "security_history.sqlite"
        
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialise les tables si elles n'existent pas."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    ports_json TEXT NOT NULL,
                    status TEXT DEFAULT 'success'
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    message TEXT NOT NULL
                )
            """)
            conn.commit()

    def save_snapshot(self, snapshot: Dict[str, Any]) -> int:
        """Enregistre un nouveau snapshot dans l'historique."""
        timestamp = snapshot.get("timestamp") or datetime.utcnow().isoformat() + "Z"
        risk_score = snapshot.get("risk_score", 0)
        ports_json = json.dumps(snapshot.get("ports", []), indent=2)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO security_snapshots (timestamp, risk_score, ports_json) VALUES (?, ?, ?)",
                (timestamp, risk_score, ports_json)
            )
            conn.commit()
            return cursor.lastrowid

    def save_alert(self, risk_score: int, message: str) -> int:
        """Enregistre une nouvelle alerte dans l'historique."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO security_alerts (timestamp, risk_score, message) VALUES (?, ?, ?)",
                (timestamp, risk_score, message)
            )
            conn.commit()
            return cursor.lastrowid

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Récupère les derniers snapshots."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, timestamp, risk_score, ports_json FROM security_snapshots ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "risk_score": row["risk_score"],
                    "ports": json.loads(row["ports_json"])
                }
                for row in rows
            ]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Récupère les dernières alertes."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, timestamp, risk_score, message FROM security_alerts ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
