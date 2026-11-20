from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from database import get_direct_connection, init_db

def seed_database():
    """Populate database with demo accounts, Rohan Menon case study, and realistic cybersecurity telemetry."""
    init_db()
    conn = get_direct_connection()
    cursor = conn.cursor()

    # Clear existing data to ensure clean state
    cursor.execute("DELETE FROM audit_logs")
    cursor.execute("DELETE FROM approval_requests")
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM login_history")
    cursor.execute("DELETE FROM users")
    try:
        cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('users', 'login_history', 'alerts', 'approval_requests', 'audit_logs')")
    except Exception:
        pass

    # Dates
    now = datetime.now()
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')
    three_days_ago = (now - timedelta(days=4)).strftime('%Y-%m-%d %H:%M:%S')
    eight_days_ago = (now - timedelta(days=8)).strftime('%Y-%m-%d %H:%M:%S')
    today_morning = now.strftime('%Y-%m-%d 08:45:12')
    yesterday = (now - timedelta(days=1)).strftime('%Y-%m-%d 14:22:10')

    # Hash passwords
    admin_pw = generate_password_hash("Admin@2026", method="scrypt")
    rohan_pw = generate_password_hash("Rohan@1234", method="scrypt")
    emp_pw = generate_password_hash("Employee@2026", method="scrypt")

    # Insert Users
    users_data = [
        # 1. Admin Account
        (
            'admin', admin_pw, 'Cybersecurity SOC Lead', 'soc.admin@saveetha.sec',
            'admin', 'SOC Lead & Security Administrator', 'IT Security',
            'Active', None, 'Active', 1, 'Authenticator App (TOTP)',
            today_morning, '192.168.1.10', 'Chennai HQ', now_str, now_str
        ),
        # 2. Rohan Menon - DEMO CASE STUDY
        (
            'r.menon', rohan_pw, 'Rohan Menon', 'r.menon@saveetha.sec',
            'employee', 'Accounts Payable Clerk', 'Finance',
            'Resigned', '2026-06-30', 'Flagged', 0, 'None',
            '2026-08-13 23:14:02', '172.16.8.44', 'Chennai', '2026-01-10 09:00:00', now_str
        ),
        # 3. Ananya Sharma - Active, Compliant, MFA Enrolled
        (
            'a.sharma', emp_pw, 'Ananya Sharma', 'a.sharma@saveetha.sec',
            'employee', 'Senior DevOps Engineer', 'IT Infrastructure',
            'Active', None, 'Active', 1, 'FIDO2 / Hardware Security Key',
            yesterday, '192.168.1.45', 'Chennai HQ', now_str, now_str
        ),
        # 4. Kavita Patel - Inactive for 4 days (3-5 days threshold warning)
        (
            'k.patel', emp_pw, 'Kavita Patel', 'k.patel@saveetha.sec',
            'employee', 'HR Generalist', 'Human Resources',
            'Active', None, 'Active', 0, 'None',
            three_days_ago, '192.168.2.18', 'Chennai HQ', now_str, now_str
        ),
        # 5. Suresh Ramesh - Resigned & Properly Suspended
        (
            's.ramesh', emp_pw, 'Suresh Ramesh', 's.ramesh@saveetha.sec',
            'employee', 'Junior Financial Auditor', 'Finance',
            'Resigned', '2026-07-15', 'Suspended', 0, 'None',
            '2026-07-15 16:55:00', '192.168.1.80', 'Chennai HQ', now_str, now_str
        ),
        # 6. Vikram Anand - Inactive for 8 days (>5 days extended dormancy)
        (
            'v.anand', emp_pw, 'Vikram Anand', 'v.anand@saveetha.sec',
            'employee', 'Supply Chain Analyst', 'Operations',
            'Active', None, 'Active', 1, 'Authenticator App (TOTP)',
            eight_days_ago, '192.168.3.102', 'Chennai HQ', now_str, now_str
        ),
        # 7. Priya Sundaram - Security Analyst (Admin backup)
        (
            'p.sundaram', admin_pw, 'Priya Sundaram', 'p.sundaram@saveetha.sec',
            'admin', 'Incident Response Specialist', 'IT Security',
            'Active', None, 'Active', 1, 'Authenticator App (TOTP)',
            today_morning, '192.168.1.15', 'Chennai HQ', now_str, now_str
        ),
        # 8. Karthik Rajan - Active Sales Rep
        (
            'k.rajan', emp_pw, 'Karthik Rajan', 'k.rajan@saveetha.sec',
            'employee', 'Enterprise Solutions Executive', 'Business Dev',
            'Active', None, 'Active', 1, 'SMS-2FA',
            today_morning, '103.21.144.12', 'Bangalore Remote', now_str, now_str
        )
    ]

    cursor.executemany("""
    INSERT INTO users (
        username, password_hash, full_name, email, role, position, department,
        employment_status, resignation_date, account_status, mfa_enabled, mfa_method,
        last_login, last_login_ip, last_login_location, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, users_data)

    # Fetch User IDs
    cursor.execute("SELECT id, username FROM users")
    user_map = {row['username']: row['id'] for row in cursor.fetchall()}

    # Insert Login History for Rohan Menon & others
    rohan_id = user_map['r.menon']
    history_data = [
        # Normal login before resignation
        (rohan_id, 'r.menon', '2026-06-25 09:12:15', '192.168.1.105', 'Chennai HQ', 'Password only', 0, 'Success', 'Low', 'Standard internal access', 0),
        # Official last working day logout
        (rohan_id, 'r.menon', '2026-06-30 17:30:00', '192.168.1.105', 'Chennai HQ', 'Password only', 0, 'Success', 'Low', 'Last working day departure', 0),
        # THE SPECIFIED CRITICAL DEMO BREACH LOGIN:
        (
            rohan_id, 'r.menon', '2026-08-13 23:14:02', '172.16.8.44', 'Chennai',
            'Password only', 0, 'Success', 'Critical',
            'POST-RESIGNATION SHADOW LOGIN: Authenticated 44 days after resignation (30 June 2026) without MFA.', 1
        ),
        # Secondary attempted exfiltration session
        (
            rohan_id, 'r.menon', '2026-08-14 02:40:11', '172.16.8.44', 'Chennai',
            'Password only', 0, 'Blocked', 'Critical',
            'Anomalous nighttime batch payroll query blocked by perimeter rule.', 1
        ),
        # Other users
        (user_map['admin'], 'admin', today_morning, '192.168.1.10', 'Chennai HQ', 'Password + MFA', 1, 'Success', 'Low', 'SOC admin console session', 0),
        (user_map['a.sharma'], 'a.sharma', yesterday, '192.168.1.45', 'Chennai HQ', 'Password + MFA', 1, 'Success', 'Low', 'DevOps deployment pipeline', 0),
        (user_map['k.patel'], 'k.patel', three_days_ago, '192.168.2.18', 'Chennai HQ', 'Password only', 0, 'Success', 'Medium', 'Dormant user authentication', 0),
        (user_map['v.anand'], 'v.anand', eight_days_ago, '192.168.3.102', 'Chennai HQ', 'Password + MFA', 1, 'Success', 'Medium', 'Last session before leave', 0)
    ]

    cursor.executemany("""
    INSERT INTO login_history (
        user_id, username, login_time, ip_address, location, auth_method, mfa_used,
        status, risk_level, risk_reason, is_suspicious
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, history_data)

    # Insert Alerts (Including Rohan Menon Critical Demo Case)
    alerts_data = [
        (
            "CRITICAL: Post-Resignation Shadow Access - Rohan Menon",
            "CRIMATHON DEMO CASE STUDY: Former Accounts Payable Clerk Rohan Menon officially resigned on 30 June 2026. On 13 August 2026 at 23:14:02, a successful authentication was logged from IP 172.16.8.44 (Chennai) using Password-only credentials. MFA was never enrolled. Unrevoked zombie credential exploited.",
            "Critical", "Shadow Credential", rohan_id, "r.menon", "172.16.8.44",
            "Pending", 1, "Immediate account quarantine, force session revocation, and alert internal audit.",
            "2026-08-13 23:15:00", None, None, None
        ),
        (
            "Warning: Account Inactive for 4 Days (3–5 Days Threshold) - Kavita Patel",
            "Account 'k.patel' (HR Generalist) has recorded no login events for 4 consecutive days. System policy Sec-4.2 requires monitoring dormant accounts to mitigate stealth credential takeover.",
            "Medium", "Dormant Account (3-5d)", user_map['k.patel'], "k.patel", "192.168.2.18",
            "Pending", 0, "Notify employee supervisor and enforce MFA upon next login.",
            three_days_ago, None, None, None
        ),
        (
            "High Risk: Extended Account Dormancy (>5 Days) - Vikram Anand",
            "Account 'v.anand' (Supply Chain Analyst) has been dormant for 8 days. Dormant accounts exceeding 5 days present heightened lateral pivot exposure.",
            "High", "Extended Dormancy (>5d)", user_map['v.anand'], "v.anand", "192.168.3.102",
            "Pending", 0, "Place in temporary dormant hold pending supervisor authorization.",
            eight_days_ago, None, None, None
        ),
        (
            "Notice: Multi-Factor Authentication Non-Compliance",
            "Employee account 'k.patel' has not enabled MFA despite handling confidential personnel records in Human Resources.",
            "Low", "MFA Non-Compliance", user_map['k.patel'], "k.patel", "192.168.2.18",
            "Resolved", 0, "Dispatched automated security advisory.",
            "2026-08-10 11:00:00", "2026-08-10 12:00:00", "admin", "Automated compliance warning email sent to user."
        )
    ]

    cursor.executemany("""
    INSERT INTO alerts (
        title, description, severity, category, user_id, username, source_ip,
        status, is_simulated_case, mitigation_action, created_at, resolved_at, resolved_by, admin_notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, alerts_data)

    # Insert Approval Requests
    approvals_data = [
        (
            "Account Reactivation", "v.anand", "v.anand",
            "Returned from 8-day operational field audit in Coimbatore. Requesting security lock clearance.",
            "High", "Pending", None, None, now_str, None
        ),
        (
            "MFA Reset & Token Re-enrollment", "k.patel", "k.patel",
            "Replaced company smartphone. Requesting fresh QR setup token for Microsoft Authenticator.",
            "Medium", "Pending", None, None, now_str, None
        ),
        (
            "Dormant Account Unfreeze", "s.ramesh", "s.ramesh",
            "Attempted access after resignation - flagged as unauthorized request.",
            "Critical", "Rejected", "Denied: Individual confirmed resigned as of 15 July 2026. Account permanently retired.",
            "admin", "2026-07-16 10:30:00", "2026-07-16 10:45:00"
        )
    ]

    cursor.executemany("""
    INSERT INTO approval_requests (
        request_type, requested_by, target_username, reason, urgency, status,
        admin_response, reviewed_by, created_at, reviewed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, approvals_data)

    # Insert Initial Audit Logs
    audit_data = [
        (
            now_str, "admin", "SYSTEM_INITIALIZATION", "Shadow Preventer Core",
            "SHADOW PREVENTER initialized for Crimathon - Saveetha Engineering College. Baseline policies loaded.",
            "192.168.1.10", "Info"
        ),
        (
            "2026-08-13 23:16:10", "SYSTEM_DETECTION_ENGINE", "CRITICAL_SHADOW_ALERT", "User: r.menon",
            "Rohan Menon account flagged: Login detected 44 days post-resignation from IP 172.16.8.44 (Chennai).",
            "127.0.0.1", "Critical"
        ),
        (
            "2026-08-10 12:00:00", "admin", "ALERT_RESOLVED", "Alert #4",
            "MFA advisory dispatched to k.patel. Marked alert as resolved.",
            "192.168.1.10", "Info"
        ),
        (
            "2026-07-16 10:45:00", "admin", "APPROVAL_REJECTED", "User: s.ramesh",
            "Rejected reactivation request for resigned employee Suresh Ramesh. Account permanently suspended.",
            "192.168.1.10", "Warning"
        ),
        (
            now_str, "admin", "POLICY_SCAN_EXECUTED", "PolicyEngine",
            "Full credential scan executed across 8 accounts. Identified 1 shadow account, 1 dormant (3-5d), 1 extended dormant.",
            "192.168.1.10", "Info"
        )
    ]

    cursor.executemany("""
    INSERT INTO audit_logs (
        timestamp, admin_username, action_type, target_entity, details, ip_address, severity
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, audit_data)

    conn.commit()
    conn.close()
    print("Shadow Preventer sample data seeded successfully!")

if __name__ == '__main__':
    seed_database()
