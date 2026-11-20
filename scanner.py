from datetime import datetime, date, timedelta
from database import get_db, get_direct_connection

def calculate_inactivity_days(last_login_str):
    """Calculate elapsed days since last login."""
    if not last_login_str:
        return 999  # Never logged in or unknown
    try:
        # Handle formats: 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DD'
        if ' ' in last_login_str:
            last_date = datetime.strptime(last_login_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
        else:
            last_date = datetime.strptime(last_login_str, '%Y-%m-%d')
        diff = datetime.now() - last_date
        return max(0, diff.days)
    except Exception:
        return 999

def run_threat_scan(db=None):
    """
    Run security analysis engine across all user accounts.
    Detects:
    1. Shadow accounts (resigned employees with active or used accounts)
    2. Dormant accounts inactive for 3-5 days
    3. Extended dormancy (>5 days)
    4. Unenrolled MFA on critical departments
    """
    close_at_end = False
    if db is None:
        db = get_direct_connection()
        close_at_end = True

    new_alerts_count = 0
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    today_date = date.today()

    users = db.execute("SELECT * FROM users").fetchall()

    for user in users:
        user_id = user['id']
        username = user['username']
        emp_status = user['employment_status']
        resignation_date_str = user['resignation_date']
        acct_status = user['account_status']
        last_login_str = user['last_login']
        mfa_enabled = user['mfa_enabled']
        department = user['department']
        position = user['position']

        # -------------------------------------------------------------
        # 1. SHADOW CREDENTIAL DETECTION (Resigned employee with active/unrevoked account)
        # -------------------------------------------------------------
        is_resigned = (emp_status == 'Resigned')
        resignation_date = None
        if resignation_date_str:
            try:
                resignation_date = datetime.strptime(resignation_date_str, '%Y-%m-%d').date()
                if resignation_date <= today_date:
                    is_resigned = True
            except Exception:
                pass

        if is_resigned:
            # Check if account is still active or flagged
            if acct_status in ['Active', 'Flagged']:
                # Check for post-resignation logins
                logins_after_resignation = []
                if resignation_date:
                    history = db.execute(
                        "SELECT * FROM login_history WHERE user_id = ? ORDER BY login_time DESC",
                        (user_id,)
                    ).fetchall()
                    for log in history:
                        try:
                            l_date = datetime.strptime(log['login_time'].split(' ')[0], '%Y-%m-%d').date()
                            if l_date >= resignation_date:
                                logins_after_resignation.append(log)
                        except Exception:
                            pass

                # Check if alert already exists
                existing_alert = db.execute(
                    """
                    SELECT id FROM alerts 
                    WHERE username = ? AND category = 'Shadow Credential' AND status IN ('Pending', 'Under Investigation')
                    """,
                    (username,)
                ).fetchone()

                if not existing_alert:
                    is_demo = 1 if username == 'r.menon' else 0
                    if logins_after_resignation:
                        most_recent = logins_after_resignation[0]
                        desc = (
                            f"CRITICAL BREACH RISK: Former employee {user['full_name']} ({position}) officially "
                            f"resigned on {resignation_date_str}, but recorded successful authentication on "
                            f"{most_recent['login_time']} from IP {most_recent['ip_address']} ({most_recent['location']}). "
                            f"Credentials were never de-provisioned!"
                        )
                    else:
                        desc = (
                            f"UNREVOKED ZOMBIE ACCOUNT: Employee {user['full_name']} ({position}) resigned on "
                            f"{resignation_date_str or 'Recorded Termination'}, yet internal account credentials "
                            f"remain ACTIVE and accessible."
                        )

                    db.execute(
                        """
                        INSERT INTO alerts (title, description, severity, category, user_id, username, source_ip, 
                                            status, is_simulated_case, mitigation_action, created_at)
                        VALUES (?, ?, 'Critical', 'Shadow Credential', ?, ?, ?, 'Pending', ?, ?, ?)
                        """,
                        (
                            f"Critical: Post-Resignation Shadow Access - {username}",
                            desc,
                            user_id,
                            username,
                            user['last_login_ip'] or 'Unknown',
                            is_demo,
                            "Immediately suspend account, terminate active tokens, and initiate access audit.",
                            now_str
                        )
                    )
                    new_alerts_count += 1

                # Update account status to 'Flagged' if it was Active
                if acct_status == 'Active':
                    db.execute("UPDATE users SET account_status = 'Flagged', updated_at = ? WHERE id = ?", (now_str, user_id))

        # -------------------------------------------------------------
        # 2. INACTIVITY DETECTION (3 - 5 Days & > 5 Days)
        # -------------------------------------------------------------
        if acct_status == 'Active' and not is_resigned:
            inactivity_days = calculate_inactivity_days(last_login_str)

            if 3 <= inactivity_days <= 5:
                # Check for existing pending alert
                existing_alert = db.execute(
                    """
                    SELECT id FROM alerts 
                    WHERE username = ? AND category = 'Dormant Account (3-5d)' AND status IN ('Pending', 'Under Investigation')
                    """,
                    (username,)
                ).fetchone()

                if not existing_alert:
                    db.execute(
                        """
                        INSERT INTO alerts (title, description, severity, category, user_id, username, source_ip, 
                                            status, is_simulated_case, mitigation_action, created_at)
                        VALUES (?, ?, 'Medium', 'Dormant Account (3-5d)', ?, ?, ?, 'Pending', 0, ?, ?)
                        """,
                        (
                            f"Warning: Inactivity Threshold Met (3-5 Days) - {username}",
                            f"Account '{username}' ({user['full_name']} - {position}) has been inactive for {inactivity_days} days. "
                            f"Subject to dormancy policy review under Sec-Policy 4.2.",
                            user_id,
                            username,
                            user['last_login_ip'] or '127.0.0.1',
                            "Monitor for anomalous reactivation or verify employee leave status.",
                            now_str
                        )
                    )
                    new_alerts_count += 1

            elif inactivity_days > 5 and inactivity_days < 900:
                # Extended Dormancy (>5 days)
                existing_alert = db.execute(
                    """
                    SELECT id FROM alerts 
                    WHERE username = ? AND category = 'Extended Dormancy (>5d)' AND status IN ('Pending', 'Under Investigation')
                    """,
                    (username,)
                ).fetchone()

                if not existing_alert:
                    db.execute(
                        """
                        INSERT INTO alerts (title, description, severity, category, user_id, username, source_ip, 
                                            status, is_simulated_case, mitigation_action, created_at)
                        VALUES (?, ?, 'High', 'Extended Dormancy (>5d)', ?, ?, ?, 'Pending', 0, ?, ?)
                        """,
                        (
                            f"High Risk: Extended Account Dormancy (>5 Days) - {username}",
                            f"Account '{username}' has remained unused for {inactivity_days} days. Unmonitored dormant accounts "
                            f"are prime targets for silent lateral compromise.",
                            user_id,
                            username,
                            user['last_login_ip'] or '127.0.0.1',
                            "Notify department supervisor and consider temporary quarantine.",
                            now_str
                        )
                    )
                    new_alerts_count += 1

        # -------------------------------------------------------------
        # 3. MFA COMPLIANCE CHECK FOR HIGH-RISK ROLES
        # -------------------------------------------------------------
        if acct_status in ['Active', 'Flagged'] and not mfa_enabled:
            high_risk_dept = department in ['Finance', 'IT Security', 'Executive', 'Operations']
            if high_risk_dept:
                existing_mfa_alert = db.execute(
                    """
                    SELECT id FROM alerts 
                    WHERE username = ? AND category = 'MFA Non-Compliance' AND status IN ('Pending', 'Under Investigation')
                    """,
                    (username,)
                ).fetchone()

                if not existing_mfa_alert and not is_resigned:
                    db.execute(
                        """
                        INSERT INTO alerts (title, description, severity, category, user_id, username, source_ip, 
                                            status, is_simulated_case, mitigation_action, created_at)
                        VALUES (?, ?, 'Medium', 'MFA Non-Compliance', ?, ?, ?, 'Pending', 0, ?, ?)
                        """,
                        (
                            f"Policy Advisory: Missing Multi-Factor Authentication - {username}",
                            f"User '{username}' operates in sensitive division '{department}', but has not configured MFA.",
                            user_id,
                            username,
                            user['last_login_ip'] or '127.0.0.1',
                            "Send automated MFA enrollment requirement notice.",
                            now_str
                        )
                    )
                    new_alerts_count += 1

    db.commit()
    if close_at_end:
        db.close()

    return new_alerts_count
