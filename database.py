import sqlite3
import os
from flask import g
from config import Config

def get_db():
    """Get database connection from Flask application context."""
    if 'db' not in g:
        # Ensure data folder exists
        os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
        g.db = sqlite3.connect(
            Config.DATABASE_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        g.db.row_factory = sqlite3.Row
        # Enable foreign key constraints
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def close_db(e=None):
    """Close the database connection at the end of request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def get_direct_connection():
    """Get direct connection for background scripts or initialization."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initialize database schema tables."""
    conn = get_direct_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL DEFAULT 'employee',
        position TEXT NOT NULL,
        department TEXT NOT NULL,
        employment_status TEXT NOT NULL DEFAULT 'Active',
        resignation_date TEXT,
        account_status TEXT NOT NULL DEFAULT 'Active',
        mfa_enabled INTEGER NOT NULL DEFAULT 0,
        mfa_method TEXT DEFAULT 'None',
        last_login TEXT,
        last_login_ip TEXT,
        last_login_location TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    # Login History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        login_time TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        location TEXT NOT NULL,
        auth_method TEXT NOT NULL DEFAULT 'Password only',
        mfa_used INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        risk_level TEXT NOT NULL DEFAULT 'Low',
        risk_reason TEXT,
        is_suspicious INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        user_id INTEGER,
        username TEXT NOT NULL,
        source_ip TEXT,
        status TEXT NOT NULL DEFAULT 'Pending',
        is_simulated_case INTEGER NOT NULL DEFAULT 0,
        mitigation_action TEXT,
        created_at TEXT NOT NULL,
        resolved_at TEXT,
        resolved_by TEXT,
        admin_notes TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    )
    """)

    # Approval Requests Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS approval_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_type TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        target_username TEXT NOT NULL,
        reason TEXT NOT NULL,
        urgency TEXT NOT NULL DEFAULT 'Medium',
        status TEXT NOT NULL DEFAULT 'Pending',
        admin_response TEXT,
        reviewed_by TEXT,
        created_at TEXT NOT NULL,
        reviewed_at TEXT
    )
    """)

    # Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        admin_username TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        details TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        severity TEXT DEFAULT 'Info'
    )
    """)

    # Create Indexes for fast querying
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_status ON users(account_status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp)")

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully at:", Config.DATABASE_PATH)
