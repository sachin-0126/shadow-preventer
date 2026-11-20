import os
import csv
import io
from datetime import datetime, date
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response, abort
)
from config import Config
from database import get_db, close_db, init_db
from auth import (
    hash_password, verify_password, get_csrf_token,
    verify_csrf_token, get_client_ip, log_audit_event,
    get_current_user, login_required, admin_required, csrf_protect
)
from scanner import run_threat_scan, calculate_inactivity_days

app = Flask(__name__)
app.config.from_object(Config)

# Register teardown
app.teardown_appcontext(close_db)

# Inject common template variables
@app.context_processor
def inject_globals():
    return {
        'current_user': get_current_user(),
        'csrf_token': get_csrf_token(),
        'now_year': datetime.now().year,
        'current_time_str': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    }

# Ensure database exists before first request
@app.before_request
def ensure_db():
    if not os.path.exists(Config.DATABASE_PATH):
        from seed_data import seed_database
        seed_database()

# -------------------------------------------------------------
# ERROR HANDLERS
# -------------------------------------------------------------
@app.errorhandler(403)
def forbidden_error(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found_error(e):
    return render_template('base.html', page_title='Page Not Found', error_msg='The requested resource does not exist.'), 404

# -------------------------------------------------------------
# AUTHENTICATION & SESSION ROUTES
# -------------------------------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('employee_portal'))
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        if 'user_id' in session:
            return redirect(url_for('index'))
        error = request.args.get('error')
        return render_template('login.html', error=error)

    # POST Login
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    client_ip = get_client_ip()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user:
        # User not found
        log_audit_event('SYSTEM', 'LOGIN_FAILURE', f'User: {username}', f'Invalid username attempted from {client_ip}', 'Warning')
        return render_template('login.html', error='Invalid username or credentials.', username_val=username)

    # Check password
    if not verify_password(password, user['password_hash']):
        # Record failed login
        db.execute(
            """
            INSERT INTO login_history (user_id, username, login_time, ip_address, location, auth_method, mfa_used, status, risk_level, risk_reason, is_suspicious)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Failed', 'Medium', 'Invalid password attempt', 1)
            """,
            (user['id'], username, now_str, client_ip, 'Local Network', 'Password only', 0)
        )
        db.commit()
        log_audit_event(username, 'LOGIN_FAILED', f'User: {username}', f'Failed password challenge from {client_ip}', 'Warning')
        return render_template('login.html', error='Invalid username or credentials.', username_val=username)

    # Check if account is suspended
    if user['account_status'] == 'Suspended':
        db.execute(
            """
            INSERT INTO login_history (user_id, username, login_time, ip_address, location, auth_method, mfa_used, status, risk_level, risk_reason, is_suspicious)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Blocked', 'High', 'Authentication blocked: Account Suspended by SOC Admin', 1)
            """,
            (user['id'], username, now_str, client_ip, 'Local Network', 'Password only', 0)
        )
        db.commit()
        log_audit_event(username, 'BLOCKED_LOGIN_SUSPENDED', f'User: {username}', f'Suspended account login attempt from {client_ip}', 'Warning')
        return render_template('login.html', error='Access Denied: This account is currently SUSPENDED by Security Administration. Contact SOC.')

    # Check for Resigned employee login (Shadow preventer alert trigger)
    is_resigned = (user['employment_status'] == 'Resigned')
    risk_level = 'Low'
    risk_reason = 'Standard login'
    is_suspicious = 0

    if is_resigned:
        risk_level = 'Critical'
        risk_reason = f"POST-RESIGNATION ACCESS: Employee resigned on {user['resignation_date'] or 'N/A'}"
        is_suspicious = 1

    # Record successful login history
    auth_method = 'Password + MFA' if user['mfa_enabled'] else 'Password only'
    db.execute(
        """
        INSERT INTO login_history (user_id, username, login_time, ip_address, location, auth_method, mfa_used, status, risk_level, risk_reason, is_suspicious)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'Success', ?, ?, ?)
        """,
        (user['id'], username, now_str, client_ip, 'Chennai', auth_method, user['mfa_enabled'], risk_level, risk_reason, is_suspicious)
    )

    # Update last login info
    db.execute(
        "UPDATE users SET last_login = ?, last_login_ip = ?, last_login_location = ?, updated_at = ? WHERE id = ?",
        (now_str, client_ip, 'Chennai', now_str, user['id'])
    )
    db.commit()

    # Establish session
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['full_name'] = user['full_name']
    session['role'] = user['role']
    session['department'] = user['department']
    get_csrf_token()  # initialize token

    log_audit_event(username, 'USER_LOGIN_SUCCESS', f'User: {username}', f'Successful authentication ({user["role"]}) from {client_ip}', 'Info')

    # Run background check for shadow preventer
    if is_resigned:
        run_threat_scan(db)

    if user['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('employee_portal'))

@app.route('/logout')
def logout():
    user = get_current_user()
    if user:
        log_audit_event(user['username'], 'USER_LOGOUT', f'User: {user["username"]}', 'User terminated active session.', 'Info')
    session.clear()
    flash('You have been logged out securely.', 'info')
    return redirect(url_for('login_page'))

# -------------------------------------------------------------
# ADMIN DASHBOARD
# -------------------------------------------------------------
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    db = get_db()

    # Run quick scan to refresh anomaly states
    run_threat_scan(db)

    # Aggregate counts
    total_employees = db.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
    active_accounts = db.execute("SELECT COUNT(*) as count FROM users WHERE account_status = 'Active'").fetchone()['count']
    suspended_accounts = db.execute("SELECT COUNT(*) as count FROM users WHERE account_status = 'Suspended'").fetchone()['count']
    flagged_accounts = db.execute("SELECT COUNT(*) as count FROM users WHERE account_status = 'Flagged'").fetchone()['count']
    resigned_count = db.execute("SELECT COUNT(*) as count FROM users WHERE employment_status = 'Resigned'").fetchone()['count']

    # Inactivity count (3-5 days & >5 days)
    users = db.execute("SELECT * FROM users").fetchall()
    dormant_3_5 = 0
    extended_dormant = 0
    for u in users:
        days = calculate_inactivity_days(u['last_login'])
        if 3 <= days <= 5 and u['account_status'] != 'Suspended':
            dormant_3_5 += 1
        elif days > 5 and u['account_status'] != 'Suspended':
            extended_dormant += 1

    total_inactive = dormant_3_5 + extended_dormant

    # Alert Counts
    pending_alerts = db.execute("SELECT COUNT(*) as count FROM alerts WHERE status IN ('Pending', 'Under Investigation')").fetchone()['count']
    critical_alerts = db.execute("SELECT COUNT(*) as count FROM alerts WHERE severity = 'Critical' AND status IN ('Pending', 'Under Investigation')").fetchone()['count']
    high_alerts = db.execute("SELECT COUNT(*) as count FROM alerts WHERE severity = 'High' AND status IN ('Pending', 'Under Investigation')").fetchone()['count']
    med_alerts = db.execute("SELECT COUNT(*) as count FROM alerts WHERE severity = 'Medium' AND status IN ('Pending', 'Under Investigation')").fetchone()['count']
    low_alerts = db.execute("SELECT COUNT(*) as count FROM alerts WHERE severity = 'Low' AND status IN ('Pending', 'Under Investigation')").fetchone()['count']

    # Pending approvals
    pending_approvals = db.execute("SELECT COUNT(*) as count FROM approval_requests WHERE status = 'Pending'").fetchone()['count']

    # Fetch Rohan Menon demo case study info
    rohan_user = db.execute("SELECT * FROM users WHERE username = 'r.menon'").fetchone()
    rohan_alert = db.execute("SELECT * FROM alerts WHERE username = 'r.menon' AND is_simulated_case = 1 ORDER BY id DESC LIMIT 1").fetchone()
    rohan_login = db.execute("SELECT * FROM login_history WHERE username = 'r.menon' AND is_suspicious = 1 ORDER BY id DESC LIMIT 1").fetchone()

    # Recent alerts stream (top 5)
    recent_alerts = db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5").fetchall()

    # Recent audit events (top 6)
    recent_audits = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 6").fetchall()

    # Department breakdown for chart
    dept_rows = db.execute("SELECT department, COUNT(*) as count FROM users GROUP BY department").fetchall()
    dept_labels = [r['department'] for r in dept_rows]
    dept_counts = [r['count'] for r in dept_rows]

    # MFA breakdown
    mfa_enrolled = db.execute("SELECT COUNT(*) as count FROM users WHERE mfa_enabled = 1").fetchone()['count']
    mfa_not_enrolled = total_employees - mfa_enrolled

    stats = {
        'total_employees': total_employees,
        'active_accounts': active_accounts,
        'inactive_accounts': total_inactive,
        'dormant_3_5': dormant_3_5,
        'extended_dormant': extended_dormant,
        'suspicious_accounts': flagged_accounts,
        'suspended_accounts': suspended_accounts,
        'resigned_count': resigned_count,
        'pending_alerts': pending_alerts,
        'critical_alerts': critical_alerts,
        'high_alerts': high_alerts,
        'medium_alerts': med_alerts,
        'low_alerts': low_alerts,
        'pending_approvals': pending_approvals,
        'mfa_enrolled': mfa_enrolled,
        'mfa_not_enrolled': mfa_not_enrolled,
        'dept_labels': dept_labels,
        'dept_counts': dept_counts
    }

    return render_template(
        'admin_dashboard.html',
        stats=stats,
        rohan_user=rohan_user,
        rohan_alert=rohan_alert,
        rohan_login=rohan_login,
        recent_alerts=recent_alerts,
        recent_audits=recent_audits
    )

# -------------------------------------------------------------
# EMPLOYEE MANAGEMENT (CRUD)
# -------------------------------------------------------------
@app.route('/admin/employees')
@login_required
@admin_required
def admin_employees():
    db = get_db()
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip()
    dept_filter = request.args.get('dept', '').strip()

    query = "SELECT * FROM users WHERE 1=1"
    params = []

    if search:
        query += " AND (username LIKE ? OR full_name LIKE ? OR email LIKE ? OR position LIKE ?)"
        wildcard = f"%{search}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])

    if status_filter:
        query += " AND account_status = ?"
        params.append(status_filter)

    if dept_filter:
        query += " AND department = ?"
        params.append(dept_filter)

    query += " ORDER BY id ASC"
    employees = db.execute(query, params).fetchall()

    # Calculate inactivity days for each employee
    enriched_employees = []
    for emp in employees:
        d = dict(emp)
        d['inactivity_days'] = calculate_inactivity_days(emp['last_login'])
        enriched_employees.append(d)

    departments = [r['department'] for r in db.execute("SELECT DISTINCT department FROM users").fetchall()]

    return render_template(
        'employees.html',
        employees=enriched_employees,
        departments=departments,
        search=search,
        status_filter=status_filter,
        dept_filter=dept_filter
    )

@app.route('/admin/employees/add', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def add_employee():
    db = get_db()
    current_admin = session.get('username')
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    username = request.form.get('username', '').strip().lower()
    full_name = request.form.get('full_name', '').strip()
    email = request.form.get('email', '').strip().lower()
    position = request.form.get('position', '').strip()
    department = request.form.get('department', '').strip()
    role = request.form.get('role', 'employee')
    employment_status = request.form.get('employment_status', 'Active')
    resignation_date = request.form.get('resignation_date') or None
    account_status = request.form.get('account_status', 'Active')
    mfa_enabled = 1 if request.form.get('mfa_enabled') == '1' else 0
    password = request.form.get('password', 'Saveetha#2026')

    if not username or not full_name or not email or not position or not department:
        flash('All mandatory fields must be completed.', 'danger')
        return redirect(url_for('admin_employees'))

    # Check duplicates
    existing = db.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone()
    if existing:
        flash(f'An account with username "{username}" or email "{email}" already exists.', 'danger')
        return redirect(url_for('admin_employees'))

    pw_hash = hash_password(password)

    db.execute(
        """
        INSERT INTO users (
            username, password_hash, full_name, email, role, position, department,
            employment_status, resignation_date, account_status, mfa_enabled, mfa_method,
            last_login, last_login_ip, last_login_location, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username, pw_hash, full_name, email, role, position, department,
            employment_status, resignation_date, account_status, mfa_enabled,
            'Authenticator App (TOTP)' if mfa_enabled else 'None',
            None, None, None, now_str, now_str
        )
    )
    db.commit()

    log_audit_event(
        current_admin, 'EMPLOYEE_ADD', f'User: {username}',
        f'Created new user profile: {full_name} ({position}, {department}) with role {role}.',
        'Info'
    )
    flash(f'Employee "{full_name}" ({username}) was created successfully.', 'success')

    # Trigger threat scan in case a resigned employee was added with an active account
    run_threat_scan(db)

    return redirect(url_for('admin_employees'))

@app.route('/admin/employees/edit/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def edit_employee(user_id):
    db = get_db()
    current_admin = session.get('username')
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('Employee record not found.', 'danger')
        return redirect(url_for('admin_employees'))

    full_name = request.form.get('full_name', '').strip()
    email = request.form.get('email', '').strip().lower()
    position = request.form.get('position', '').strip()
    department = request.form.get('department', '').strip()
    role = request.form.get('role', user['role'])
    employment_status = request.form.get('employment_status', user['employment_status'])
    resignation_date = request.form.get('resignation_date') or None
    account_status = request.form.get('account_status', user['account_status'])
    mfa_enabled = 1 if request.form.get('mfa_enabled') == '1' else 0
    new_password = request.form.get('new_password', '').strip()

    if not full_name or not email or not position or not department:
        flash('Mandatory fields missing.', 'danger')
        return redirect(url_for('admin_employees'))

    if new_password:
        pw_hash = hash_password(new_password)
        db.execute(
            """
            UPDATE users SET full_name = ?, email = ?, position = ?, department = ?, role = ?,
                             employment_status = ?, resignation_date = ?, account_status = ?,
                             mfa_enabled = ?, password_hash = ?, updated_at = ?
            WHERE id = ?
            """,
            (full_name, email, position, department, role, employment_status, resignation_date, account_status, mfa_enabled, pw_hash, now_str, user_id)
        )
    else:
        db.execute(
            """
            UPDATE users SET full_name = ?, email = ?, position = ?, department = ?, role = ?,
                             employment_status = ?, resignation_date = ?, account_status = ?,
                             mfa_enabled = ?, updated_at = ?
            WHERE id = ?
            """,
            (full_name, email, position, department, role, employment_status, resignation_date, account_status, mfa_enabled, now_str, user_id)
        )
    db.commit()

    log_audit_event(
        current_admin, 'EMPLOYEE_UPDATE', f'User: {user["username"]}',
        f'Updated profile details for {user["username"]}: Status={account_status}, Employment={employment_status}',
        'Info'
    )
    flash(f'Employee record for "{user["username"]}" updated successfully.', 'success')

    run_threat_scan(db)
    return redirect(url_for('admin_employees'))

@app.route('/admin/employees/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def delete_employee(user_id):
    db = get_db()
    current_admin = session.get('username')

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('Employee not found.', 'danger')
        return redirect(url_for('admin_employees'))

    if user['username'] == 'admin' or user['id'] == session.get('user_id'):
        flash('Security policy prohibits deleting the primary SOC Administrator account.', 'danger')
        return redirect(url_for('admin_employees'))

    username = user['username']
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    log_audit_event(
        current_admin, 'EMPLOYEE_DELETE', f'User: {username}',
        f'Permanently purged user account and associated credentials for {username}.',
        'Warning'
    )
    flash(f'Account "{username}" has been removed from system directory.', 'info')
    return redirect(url_for('admin_employees'))

# -------------------------------------------------------------
# CREDENTIAL MONITORING & SHADOW DETECTOR
# -------------------------------------------------------------
@app.route('/admin/monitoring')
@login_required
@admin_required
def credential_monitoring():
    db = get_db()
    run_threat_scan(db)

    users = db.execute("SELECT * FROM users ORDER BY account_status DESC, last_login DESC").fetchall()
    enriched = []

    for u in users:
        d = dict(u)
        inact_days = calculate_inactivity_days(u['last_login'])
        d['inactivity_days'] = inact_days
        # Compute dynamic risk score (0-100)
        risk = 10
        if u['employment_status'] == 'Resigned' and u['account_status'] != 'Suspended':
            risk = 95
        elif u['account_status'] == 'Flagged':
            risk = 85
        elif inact_days > 5 and u['account_status'] != 'Suspended':
            risk = 70
        elif 3 <= inact_days <= 5 and u['account_status'] != 'Suspended':
            risk = 50
        if not u['mfa_enabled']:
            risk = min(100, risk + 15)
        d['risk_score'] = risk
        enriched.append(d)

    # Fetch Rohan Menon specific details
    rohan_info = next((item for item in enriched if item['username'] == 'r.menon'), None)

    return render_template('monitoring.html', accounts=enriched, rohan_info=rohan_info)

# -------------------------------------------------------------
# ACCOUNT SUSPENSION & REACTIVATION
# -------------------------------------------------------------
@app.route('/admin/account/suspend/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def suspend_account(user_id):
    db = get_db()
    current_admin = session.get('username')
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    reason = request.form.get('reason', 'Security isolation / administrative quarantine.').strip()

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('User account not found.', 'danger')
        return redirect(request.referrer or url_for('credential_monitoring'))

    if user['username'] == 'admin' or user['id'] == session.get('user_id'):
        flash('Cannot suspend active SOC Administrator account.', 'danger')
        return redirect(request.referrer or url_for('credential_monitoring'))

    db.execute("UPDATE users SET account_status = 'Suspended', updated_at = ? WHERE id = ?", (now_str, user_id))
    db.commit()

    log_audit_event(
        current_admin, 'ACCOUNT_SUSPEND', f'User: {user["username"]}',
        f'Administrator suspended account {user["username"]}. Reason: {reason}',
        'Warning'
    )
    flash(f'Account "{user["username"]}" has been SUSPENDED and isolated immediately.', 'warning')
    return redirect(request.referrer or url_for('credential_monitoring'))

@app.route('/admin/account/reactivate/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def reactivate_account(user_id):
    db = get_db()
    current_admin = session.get('username')
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    reason = request.form.get('reason', 'Administrative clearance verified.').strip()

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('User account not found.', 'danger')
        return redirect(request.referrer or url_for('credential_monitoring'))

    db.execute("UPDATE users SET account_status = 'Active', updated_at = ? WHERE id = ?", (now_str, user_id))
    db.commit()

    log_audit_event(
        current_admin, 'ACCOUNT_REACTIVATE', f'User: {user["username"]}',
        f'Administrator reactivated account {user["username"]}. Authorization: {reason}',
        'Info'
    )
    flash(f'Account "{user["username"]}" has been REACTIVATED and restored to normal state.', 'success')
    return redirect(request.referrer or url_for('credential_monitoring'))

# -------------------------------------------------------------
# ALERT MANAGEMENT
# -------------------------------------------------------------
@app.route('/admin/alerts')
@login_required
@admin_required
def admin_alerts():
    db = get_db()
    severity_filter = request.args.get('severity', '').strip()
    status_filter = request.args.get('status', '').strip()

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity_filter:
        query += " AND severity = ?"
        params.append(severity_filter)

    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)

    query += " ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, id DESC"
    alerts = db.execute(query, params).fetchall()

    return render_template(
        'alerts.html',
        alerts=alerts,
        severity_filter=severity_filter,
        status_filter=status_filter
    )

@app.route('/admin/alerts/resolve/<int:alert_id>', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def resolve_alert(alert_id):
    db = get_db()
    current_admin = session.get('username')
    notes = request.form.get('notes', 'Incident verified and mitigated by SOC Lead.').strip()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    alert = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        flash('Alert not found.', 'danger')
        return redirect(url_for('admin_alerts'))

    db.execute(
        """
        UPDATE alerts SET status = 'Resolved', resolved_at = ?, resolved_by = ?, admin_notes = ?
        WHERE id = ?
        """,
        (now_str, current_admin, notes, alert_id)
    )
    db.commit()

    log_audit_event(
        current_admin, 'ALERT_RESOLVED', f'Alert #{alert_id} ({alert["category"]})',
        f'Resolved alert for {alert["username"]}. Notes: {notes}',
        'Info'
    )
    flash(f'Alert #{alert_id} marked as RESOLVED.', 'success')
    return redirect(url_for('admin_alerts'))

@app.route('/admin/alerts/reject/<int:alert_id>', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def reject_alert(alert_id):
    db = get_db()
    current_admin = session.get('username')
    reason = request.form.get('reason', 'Dismissed as false positive / sanctioned activity.').strip()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    alert = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        flash('Alert not found.', 'danger')
        return redirect(url_for('admin_alerts'))

    db.execute(
        """
        UPDATE alerts SET status = 'Dismissed', resolved_at = ?, resolved_by = ?, admin_notes = ?
        WHERE id = ?
        """,
        (now_str, current_admin, reason, alert_id)
    )
    db.commit()

    log_audit_event(
        current_admin, 'ALERT_DISMISSED', f'Alert #{alert_id}',
        f'Dismissed alert for {alert["username"]}. Reason: {reason}',
        'Warning'
    )
    flash(f'Alert #{alert_id} DISMISSED by administrator.', 'info')
    return redirect(url_for('admin_alerts'))

@app.route('/admin/alerts/mitigate/<int:alert_id>', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def mitigate_alert(alert_id):
    """One-click mitigation: suspend user and resolve alert immediately."""
    db = get_db()
    current_admin = session.get('username')
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    alert = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        flash('Alert not found.', 'danger')
        return redirect(url_for('admin_alerts'))

    # Suspend user
    if alert['user_id']:
        db.execute("UPDATE users SET account_status = 'Suspended', updated_at = ? WHERE id = ?", (now_str, alert['user_id']))

    # Update alert
    notes = f"Auto-mitigation executed: Account '{alert['username']}' quarantined and access revoked by {current_admin}."
    db.execute(
        """
        UPDATE alerts SET status = 'Resolved', resolved_at = ?, resolved_by = ?, admin_notes = ?
        WHERE id = ?
        """,
        (now_str, current_admin, notes, alert_id)
    )
    db.commit()

    log_audit_event(
        current_admin, 'AUTO_MITIGATION_EXECUTED', f'User: {alert["username"]}',
        f'Quarantined account and resolved alert #{alert_id} under mitigation policy.',
        'Critical'
    )
    flash(f'Mitigation executed: Account "{alert["username"]}" suspended and Alert #{alert_id} resolved.', 'warning')
    return redirect(url_for('admin_alerts'))

# -------------------------------------------------------------
# APPROVALS & REJECTIONS SYSTEM
# -------------------------------------------------------------
@app.route('/admin/approvals')
@login_required
@admin_required
def admin_approvals():
    db = get_db()
    status_filter = request.args.get('status', '').strip()

    query = "SELECT * FROM approval_requests WHERE 1=1"
    params = []
    if status_filter:
        query += " AND status = ?"
        params.append(status_filter)

    query += " ORDER BY CASE status WHEN 'Pending' THEN 1 ELSE 2 END, id DESC"
    requests_list = db.execute(query, params).fetchall()

    return render_template('approvals.html', requests=requests_list, status_filter=status_filter)

@app.route('/admin/approvals/approve/<int:req_id>', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def approve_request(req_id):
    db = get_db()
    current_admin = session.get('username')
    notes = request.form.get('notes', 'Approved by SOC Administrator after verification.').strip()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    req = db.execute("SELECT * FROM approval_requests WHERE id = ?", (req_id,)).fetchone()
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('admin_approvals'))

    # Execute matching action if applicable
    target_user = db.execute("SELECT * FROM users WHERE username = ?", (req['target_username'],)).fetchone()
    if target_user:
        if req['request_type'] == 'Account Reactivation':
            db.execute("UPDATE users SET account_status = 'Active', updated_at = ? WHERE id = ?", (now_str, target_user['id']))
        elif req['request_type'] == 'MFA Reset & Token Re-enrollment':
            db.execute("UPDATE users SET mfa_enabled = 1, mfa_method = 'Authenticator App (TOTP)', updated_at = ? WHERE id = ?", (now_str, target_user['id']))

    db.execute(
        """
        UPDATE approval_requests SET status = 'Approved', admin_response = ?, reviewed_by = ?, reviewed_at = ?
        WHERE id = ?
        """,
        (notes, current_admin, now_str, req_id)
    )
    db.commit()

    log_audit_event(
        current_admin, 'APPROVAL_GRANTED', f'Request #{req_id} ({req["request_type"]})',
        f'Approved request for {req["target_username"]}. Notes: {notes}',
        'Info'
    )
    flash(f'Request #{req_id} for "{req["target_username"]}" has been APPROVED.', 'success')
    return redirect(url_for('admin_approvals'))

@app.route('/admin/approvals/reject/<int:req_id>', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def reject_request(req_id):
    db = get_db()
    current_admin = session.get('username')
    reason = request.form.get('reason', 'Security request denied due to policy requirements.').strip()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    req = db.execute("SELECT * FROM approval_requests WHERE id = ?", (req_id,)).fetchone()
    if not req:
        flash('Request not found.', 'danger')
        return redirect(url_for('admin_approvals'))

    db.execute(
        """
        UPDATE approval_requests SET status = 'Rejected', admin_response = ?, reviewed_by = ?, reviewed_at = ?
        WHERE id = ?
        """,
        (reason, current_admin, now_str, req_id)
    )
    db.commit()

    log_audit_event(
        current_admin, 'APPROVAL_REJECTED', f'Request #{req_id} ({req["request_type"]})',
        f'Rejected request for {req["target_username"]}. Reason: {reason}',
        'Warning'
    )
    flash(f'Request #{req_id} for "{req["target_username"]}" has been REJECTED.', 'warning')
    return redirect(url_for('admin_approvals'))

# -------------------------------------------------------------
# AUDIT LOGS & EXPORT
# -------------------------------------------------------------
@app.route('/admin/audit-logs')
@login_required
@admin_required
def admin_audit_logs():
    db = get_db()
    severity_filter = request.args.get('severity', '').strip()
    action_filter = request.args.get('action', '').strip()

    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []

    if severity_filter:
        query += " AND severity = ?"
        params.append(severity_filter)

    if action_filter:
        query += " AND action_type LIKE ?"
        params.append(f"%{action_filter}%")

    query += " ORDER BY id DESC LIMIT 200"
    logs = db.execute(query, params).fetchall()

    action_types = [r['action_type'] for r in db.execute("SELECT DISTINCT action_type FROM audit_logs").fetchall()]

    return render_template(
        'audit_logs.html',
        logs=logs,
        action_types=action_types,
        severity_filter=severity_filter,
        action_filter=action_filter
    )

@app.route('/admin/audit-logs/export')
@login_required
@admin_required
def export_audit_logs():
    db = get_db()
    logs = db.execute("SELECT * FROM audit_logs ORDER BY id DESC").fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Log ID', 'Timestamp', 'Admin Username', 'Action Type', 'Target Entity', 'Details', 'Source IP', 'Severity'])

    for log in logs:
        writer.writerow([
            log['id'], log['timestamp'], log['admin_username'], log['action_type'],
            log['target_entity'], log['details'], log['ip_address'], log['severity']
        ])

    output.seek(0)
    filename = f"shadow_preventer_audit_trail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

# -------------------------------------------------------------
# REAL-TIME SCAN API
# -------------------------------------------------------------
@app.route('/admin/api/scan', methods=['POST'])
@login_required
@admin_required
@csrf_protect
def api_run_scan():
    db = get_db()
    current_admin = session.get('username')
    new_alerts = run_threat_scan(db)

    log_audit_event(
        current_admin, 'POLICY_SCAN_TRIGGERED', 'SecurityEngine',
        f'Manual deep scan executed across all credentials. Detected {new_alerts} new threat indicators.',
        'Info'
    )
    return jsonify({
        'success': True,
        'message': f'Scan complete. {new_alerts} new anomalies or policy violations detected.',
        'new_alerts': new_alerts
    })

# -------------------------------------------------------------
# EMPLOYEE DASHBOARD & SELF-SERVICE PORTAL
# -------------------------------------------------------------
@app.route('/employee/portal')
@login_required
def employee_portal():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_page'))

    db = get_db()
    # Fetch user personal login history
    history = db.execute(
        "SELECT * FROM login_history WHERE user_id = ? ORDER BY id DESC LIMIT 15",
        (user['id'],)
    ).fetchall()

    # Fetch user pending approval requests
    requests_list = db.execute(
        "SELECT * FROM approval_requests WHERE requested_by = ? OR target_username = ? ORDER BY id DESC",
        (user['username'], user['username'])
    ).fetchall()

    # Calculate personal security score
    sec_score = 100
    if not user['mfa_enabled']:
        sec_score -= 30
    if user['account_status'] == 'Flagged':
        sec_score -= 40
    elif user['account_status'] == 'Suspended':
        sec_score = 0

    inactivity_days = calculate_inactivity_days(user['last_login'])

    return render_template(
        'employee_portal.html',
        user=user,
        history=history,
        requests=requests_list,
        sec_score=sec_score,
        inactivity_days=inactivity_days
    )

@app.route('/employee/request', methods=['POST'])
@login_required
@csrf_protect
def submit_employee_request():
    user = get_current_user()
    db = get_db()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    request_type = request.form.get('request_type', '').strip()
    reason = request.form.get('reason', '').strip()
    urgency = request.form.get('urgency', 'Medium')

    if not request_type or not reason:
        flash('Request type and reason description are required.', 'danger')
        return redirect(url_for('employee_portal'))

    db.execute(
        """
        INSERT INTO approval_requests (request_type, requested_by, target_username, reason, urgency, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'Pending', ?)
        """,
        (request_type, user['username'], user['username'], reason, urgency, now_str)
    )
    db.commit()

    log_audit_event(
        user['username'], 'REQUEST_SUBMITTED', f'Request: {request_type}',
        f'User {user["username"]} submitted request: {reason}',
        'Info'
    )
    flash('Your security request has been submitted to the SOC Administrator.', 'success')
    return redirect(url_for('employee_portal'))

@app.route('/employee/toggle-mfa', methods=['POST'])
@login_required
@csrf_protect
def toggle_mfa():
    user = get_current_user()
    db = get_db()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    new_mfa_state = 0 if user['mfa_enabled'] else 1
    method = 'Authenticator App (TOTP)' if new_mfa_state else 'None'

    db.execute(
        "UPDATE users SET mfa_enabled = ?, mfa_method = ?, updated_at = ? WHERE id = ?",
        (new_mfa_state, method, now_str, user['id'])
    )
    db.commit()

    status_str = "ENABLED" if new_mfa_state else "DISABLED"
    log_audit_event(
        user['username'], 'MFA_STATUS_CHANGED', f'User: {user["username"]}',
        f'MFA {status_str} by user in self-service portal.',
        'Info'
    )
    flash(f'Multi-Factor Authentication has been {status_str}.', 'success')
    return redirect(url_for('employee_portal'))

@app.route('/employee/report-suspicious', methods=['POST'])
@login_required
@csrf_protect
def report_suspicious_activity():
    user = get_current_user()
    db = get_db()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    client_ip = get_client_ip()

    description = request.form.get('description', 'User reported unrecognized login or credential anomaly.').strip()

    db.execute(
        """
        INSERT INTO alerts (title, description, severity, category, user_id, username, source_ip, status, mitigation_action, created_at)
        VALUES (?, ?, 'High', 'User Reported Anomaly', ?, ?, ?, 'Pending', 'Investigate user session and consider temporary credential reset.', ?)
        """,
        (
            f"User Incident Report: {user['username']}",
            f"Employee {user['full_name']} ({user['position']}) submitted security report: '{description}'",
            user['id'],
            user['username'],
            client_ip,
            now_str
        )
    )
    db.commit()

    log_audit_event(
        user['username'], 'USER_INCIDENT_REPORTED', f'User: {user["username"]}',
        f'Security report filed by employee: {description}',
        'Warning'
    )
    flash('Security report successfully dispatched to SOC Incident Responders.', 'warning')
    return redirect(url_for('employee_portal'))

if __name__ == '__main__':
    print("=================================================================")
    print("       SHADOW PREVENTER - CRIMATHON CYBERSECURITY PORTAL         ")
    print("                 SAVEETHA ENGINEERING COLLEGE                   ")
    print("=================================================================")
    print(" Server launching on http://127.0.0.1:5000")
    print(" Demo Admin:     admin   / Admin@2026")
    print(" Demo Employee:  r.menon / Rohan@1234  (Rohan Menon Case Study)")
    print("=================================================================")
    app.run(host='0.0.0.0', port=5000, debug=True)
