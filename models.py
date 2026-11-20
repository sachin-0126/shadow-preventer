"""
Data models and helper abstractions for SHADOW PREVENTER.
Provides typed access to SQLite entities: User, LoginHistory, Alert, ApprovalRequest, and AuditLog.
"""

from database import get_db

class UserModel:
    @staticmethod
    def get_by_id(user_id):
        db = get_db()
        return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    @staticmethod
    def get_by_username(username):
        db = get_db()
        return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    @staticmethod
    def get_all(order_by="id ASC"):
        db = get_db()
        return db.execute(f"SELECT * FROM users ORDER BY {order_by}").fetchall()

class AlertModel:
    @staticmethod
    def get_pending():
        db = get_db()
        return db.execute(
            "SELECT * FROM alerts WHERE status IN ('Pending', 'Under Investigation') ORDER BY id DESC"
        ).fetchall()

    @staticmethod
    def get_by_severity(severity):
        db = get_db()
        return db.execute(
            "SELECT * FROM alerts WHERE severity = ? ORDER BY id DESC", (severity,)
        ).fetchall()

class AuditLogModel:
    @staticmethod
    def get_recent(limit=50):
        db = get_db()
        return db.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
