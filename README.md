<<<<<<< HEAD
# SHADOW PREVENTER

**Autonomous Credential Threat Defense & Shadow Account Prevention System**  
*Crimathon Project &bull; Saveetha Engineering College*

---

## 🎯 Executive Overview

Organizations suffer critical data breaches when accounts belonging to departed or resigned personnel remain active, or when dormant credentials linger unmonitored. Threat actors compromise these unmanaged **"Shadow Accounts"** (or **"Zombie Credentials"**) to gain persistent, undetected foothold in enterprise networks.

**SHADOW PREVENTER** is an enterprise-grade cybersecurity command and surveillance system designed to autonomously identify, flag, quarantine, and audit orphan credentials, post-resignation breach attempts, dormancy threshold violations (3–5 days), and unauthorized privilege escalations.

---

## 🛡️ Key Features & Technical Capabilities

| # | Feature | Technical Implementation |
|---|---|---|
| **1** | **Role-Based Authentication** | Secure `scrypt` password hashing via Werkzeug, session token rotation, custom CSRF protection tokens, and role-based access control (`admin` vs `employee`). |
| **2** | **Executive SOC Dashboard** | Real-time KPI telemetry (Total Employees, Active Accounts, Inactive Accounts, Suspicious Accounts, Pending Alerts) + 4 interactive Chart.js visualizations. |
| **3** | **Employee Directory & CRUD** | Complete identity provisioning lifecycle: add, update, search, filter by department, and delete employee records. |
| **4** | **Credential Surveillance Matrix** | Deep credential audit tracking username, last login timestamp, origin IP & location, MFA posture, dormancy duration, dynamic calculated risk score (0–100%), and status. |
| **5** | **Shadow Account Detection** | Autonomous correlation engine that immediately flags accounts belonging to resigned personnel (`employment_status == 'Resigned'`) with active credentials or post-resignation logins. |
| **6** | **3–5 Day Dormancy Sentinel** | Automated inactivity tracker that categorizes accounts inactive for 3 to 5 days under security review, and >5 days under high zombie risk. |
| **7** | **Four-Tier Alert Management** | Incident response queue categorized by **Critical**, **High**, **Medium**, and **Low** severity with 1-click auto-mitigation, resolution notes, and dismissal workflows. |
| **8** | **Admin Approval / Rejection Queue** | Dual-control clearance system enabling administrators to approve or reject employee access requests (MFA token resets, dormancy clearance, unfreeze requests). |
| **9** | **Account Quarantine & Reactivation** | Instant credential isolation and suspension with confirmation modal, blocking subsequent logins with immediate enforcement. |
| **10** | **Immutable Audit Trail** | Tamper-evident log recording every administrative decision, quarantine, policy trigger, target entity, origin IP, and timestamp, with 1-click CSV export. |
| **11** | **Employee Self-Service Portal** | Dedicated interface displaying personal security health score, MFA simulation toggle, personal login history, and incident reporting. |

---

## 🧪 Flagship Demo Case Study: Rohan Menon

The application comes pre-configured with the simulated breach case study specified for the Saveetha Engineering College Crimathon evaluation:

* **Subject Name:** Rohan Menon
* **Assigned Position:** Accounts Payable Clerk
* **Department:** Finance
* **Official Last Working Day:** **30 June 2026**
* **Username:** `r.menon`
* **Suspicious Authentication:** **13 August 2026 at 23:14:02 IST** (44 days after resignation)
* **Origin IP:** `172.16.8.44`
* **Location:** Chennai
* **Authentication Method:** Password only
* **MFA Status:** Not enrolled
* **Result:** Success (Unrevoked Credential Compromised)
* **Threat Classification:** **CRITICAL SEVERITY** &bull; Shadow Credential Breach
* **System Action:** Automatically flagged account status as `Flagged (Shadow Risk)`, generated Critical Alert #1, and presented 1-click **"Quarantine & Suspend"** button in SOC Dashboard.

---

## 🔑 Demo Login Credentials

For testing and demonstration, use any of the pre-seeded accounts below:

| Role | Username | Password | Purpose / Scenario |
|---|---|---|---|
| **SOC Administrator** | `admin` | `Admin@2026` | Full access to SOC Dashboard, Employee CRUD, Monitoring, Alerts, Approvals & Audit Logs. |
| **Demo Breach Case** | `r.menon` | `Rohan@1234` | **Rohan Menon** &mdash; Resigned Accounts Payable Clerk (Simulated Breach Demonstration). |
| **Active Employee** | `a.sharma` | `Employee@2026` | Senior DevOps Engineer &mdash; Compliant, MFA enrolled, healthy identity score. |
| **Dormant Employee** | `k.patel` | `Employee@2026` | HR Generalist &mdash; Inactive for 4 days (demonstrating the 3–5 day dormancy warning policy). |

> **Tip:** The login page features **1-Click Quick Fill buttons** for effortless evaluation by judges and examiners!

---

## 💻 Tech Stack & Architecture

* **Backend:** Python 3 &bull; Flask &bull; Werkzeug Security
* **Database:** SQLite 3 (`data/shadow_preventer.db`) with relational integrity and indexes
* **Frontend:** HTML5 &bull; CSS3 (Cybersecurity Dark Maroon Design System `#08090d` / `#8B1E3F` / `#ef4444`) &bull; Vanilla JavaScript ES6+
* **Analytics & Visualizations:** Chart.js (bundled locally for 100% offline operation)
* **Security Layer:**
  * Password hashing: Werkzeug `scrypt`
  * Role-based access control (RBAC): `@admin_required` and `@login_required`
  * Cross-Site Request Forgery (CSRF) protection on all state-mutating requests
  * Client IP tracking and forensic timestamping
  * Custom 403 Forbidden page preventing employees from accessing administrative routes

---

## 🚀 How to Run the Website

### Method 1: One-Click Startup (Windows)
Double-click `run.bat` in the project root folder.

### Method 2: Manual Terminal Startup

1. Open PowerShell or Command Prompt in the `d:\Shadow` directory:
   ```powershell
   cd d:\Shadow
   ```

2. (Optional) Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Seed the database with the initial demo dataset (including Rohan Menon):
   ```powershell
   python seed_data.py
   ```

4. Launch the Flask web server:
   ```powershell
   python app.py
   ```

5. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## 📁 Project Directory Structure

```
d:\Shadow/
├── app.py                     # Main Flask web application, routing, APIs & RBAC enforcement
├── config.py                  # System configuration and session security settings
├── database.py                # Database connection factory & schema definition
├── models.py                  # Schema definitions & data helper models
├── auth.py                    # Password hashing, CSRF verification, decorators & audit helper
├── scanner.py                 # Autonomous threat detection engine (shadow accounts, dormancy)
├── seed_data.py               # Database seeder with sample accounts & Rohan Menon breach case
├── requirements.txt           # Python package requirements
├── run.bat                    # One-click Windows launch script
├── README.md                  # Comprehensive project documentation
├── data/
│   └── shadow_preventer.db    # SQLite database (auto-created)
├── static/
│   ├── css/
│   │   ├── style.css          # Core dark maroon & obsidian cybersecurity theme
│   │   └── dashboard.css      # SOC dashboard cards, case study banner, charts styling
│   ├── js/
│   │   ├── main.js            # Global utilities, digital clock, modal handlers, toast alerts
│   │   └── admin_dashboard.js # Chart.js integrations & real-time scan triggers
│   └── vendor/
│       └── chart.min.js       # Offline bundled Chart.js v4.4.1 library
└── templates/
    ├── base.html              # Master layout with cyber sidebar, header & global confirmation
    ├── login.html             # High-tech login with role switcher & 1-click demo logins
    ├── admin_dashboard.html   # SOC command center, Rohan Menon hero banner, KPI metrics & charts
    ├── employees.html         # Employee management (add, edit, delete, status toggle)
    ├── monitoring.html        # Credential surveillance grid & shadow detector matrix
    ├── alerts.html            # Alert triage center (Critical, High, Medium, Low severity)
    ├── approvals.html         # Administrative authorization & rejection queue
    ├── audit_logs.html        # Immutable forensic audit trail with CSV export
    ├── employee_portal.html   # Employee self-service hub, login history & incident report
    └── 403.html               # RBAC violation security warning page
```

---

## 🏆 Project Credits

**Crimathon 2026 &bull; Saveetha Engineering College**  
*Project: SHADOW PREVENTER &mdash; Autonomous Shadow Account Prevention System*
=======
# shadow-preventer
>>>>>>> d5c766ae338e94e4532af486df84387d1869fe5a
