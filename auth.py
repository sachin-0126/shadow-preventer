import secrets
from functools import wraps
from datetime import datetime
from flask import session, redirect, url_for, request, abort, g, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db

def hash_password(password: str) -> str:
    """Generate secure hash for password."""
    return generate_password_hash(password, method='scrypt')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against scrypt/pbkdf2 hash."""
    return check_password_hash(hashed, password)

def get_csrf_token() -> str:
    """Generate or retrieve current CSRF token stored in session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def verify_csrf_token(token: str) -> bool:
    """Verify submitted CSRF token matches session token."""
    stored = session.get('_csrf_token')
    if not stored or not token:
        return False
    return secrets.compare_digest(stored, token)

def get_client_ip() -> str:
    """Extract real or remote client IP address."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def log_audit_event(admin_username: str, action_type: str, target_entity: str, details: str, severity: str = 'Info'):
    """Record administrative or security action in audit logs."""
    try:
        db = get_db()
        ip = get_client_ip()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute(
            """
            INSERT INTO audit_logs (timestamp, admin_username, action_type, target_entity, details, ip_address, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (now, admin_username, action_type, target_entity, details, ip, severity)
        )
        db.commit()
    except Exception as e:
        print(f"Error logging audit event: {e}")

def get_current_user():
    """Retrieve full user profile of currently logged-in user."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

def login_required(f):
    """Decorator requiring authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Authentication required. Please log in.'}), 401
            return redirect(url_for('login_page', next=request.url))
        
        # Verify account is still active/not suspended
        user = get_current_user()
        if not user or user['account_status'] == 'Suspended':
            session.clear()
            if request.is_json:
                return jsonify({'success': False, 'message': 'Account is suspended. Contact SOC Administrator.'}), 403
            return redirect(url_for('login_page', error='Your account has been suspended by the Security Administrator.'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator requiring authenticated user with 'admin' role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Authentication required.'}), 401
            return redirect(url_for('login_page', next=request.url))
            
        role = session.get('role')
        if role != 'admin':
            # Record unauthorized attempt
            user = get_current_user()
            username = user['username'] if user else 'Unknown'
            log_audit_event(
                admin_username=username,
                action_type='UNAUTHORIZED_ACCESS_ATTEMPT',
                target_entity=f'Route: {request.path}',
                details=f'Non-admin user {username} (Role: {role}) attempted to access protected administrative endpoint.',
                severity='Critical'
            )
            if request.is_json:
                return jsonify({'success': False, 'message': 'Access denied: Administrator privileges required.'}), 403
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def csrf_protect(f):
    """Decorator to enforce CSRF token on mutating endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_app.config.get('TESTING'):
            return f(*args, **kwargs)

        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Accept token from form or header
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not token and request.is_json:
                json_data = request.get_json(silent=True) or {}
                token = json_data.get('csrf_token')
            
            if not verify_csrf_token(token):
                if request.is_json:
                    return jsonify({'success': False, 'message': 'Invalid or missing CSRF security token.'}), 400
                abort(400, description="Invalid or missing CSRF token.")
        return f(*args, **kwargs)
    return decorated_function
