/**
 * ============================================================================
 * SHADOW PREVENTER - FRONTEND APPLICATION JAVASCRIPT
 * Autonomous Ghost Access & Credential Threat Defense
 * ============================================================================
 */

// LocalStorage Keys
const STORAGE_KEY_PREFIX = 'SHADOW_PREVENTER_';
const KEYS = {
  EMPLOYEES: STORAGE_KEY_PREFIX + 'EMPLOYEES',
  CREDENTIALS: STORAGE_KEY_PREFIX + 'CREDENTIALS',
  ALERTS: STORAGE_KEY_PREFIX + 'ALERTS',
  APPROVALS: STORAGE_KEY_PREFIX + 'APPROVALS',
  AUDIT: STORAGE_KEY_PREFIX + 'AUDIT',
  SESSION: STORAGE_KEY_PREFIX + 'SESSION'
};

// Global State
let appState = {
  currentUser: null,
  employees: [],
  credentials: [],
  alerts: [],
  approvals: [],
  auditLogs: [],
  activeView: 'dashboardView',
  charts: {
    activity: null,
    status: null
  }
};

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initClock();
  loadOrSeedData();
  checkExistingSession();
});

function initClock() {
  const clockEl = document.getElementById('digitalClockDisplay');
  if (!clockEl) return;

  function update() {
    const now = new Date();
    const utcHours = String(now.getUTCHours()).padStart(2, '0');
    const utcMins = String(now.getUTCMinutes()).padStart(2, '0');
    const utcSecs = String(now.getUTCSeconds()).padStart(2, '0');
    const localStr = now.toLocaleTimeString();
    clockEl.innerHTML = `<i class="fas fa-clock"></i> <span>${localStr}</span> <small style="color: #64748B; margin-left: 6px;">[UTC ${utcHours}:${utcMins}:${utcSecs}]</small>`;
  }
  update();
  setInterval(update, 1000);
}

// ============================================================================
// DATA SEEDING & LOCAL STORAGE
// ============================================================================
function loadOrSeedData(forceReset = false) {
  if (forceReset || !localStorage.getItem(KEYS.EMPLOYEES)) {
    // 1. Initial Employees (including Rohan Menon demo breach case)
    const initialEmployees = [
      {
        name: 'Rohan Menon',
        id: 'SEC-1088',
        department: 'Finance',
        designation: 'Accounts Payable Clerk',
        joiningDate: '2023-04-12',
        lastWorkingDate: '2026-06-30',
        status: 'Resigned'
      },
      {
        name: 'Ananya Sharma',
        id: 'SEC-1042',
        department: 'IT Infrastructure',
        designation: 'Senior DevOps Engineer',
        joiningDate: '2022-08-15',
        lastWorkingDate: '',
        status: 'Active'
      },
      {
        name: 'Kavita Patel',
        id: 'SEC-1055',
        department: 'Human Resources',
        designation: 'HR Generalist',
        joiningDate: '2023-01-10',
        lastWorkingDate: '',
        status: 'Active'
      },
      {
        name: 'Vikram Anand',
        id: 'SEC-1019',
        department: 'Operations',
        designation: 'Supply Chain Analyst',
        joiningDate: '2021-11-04',
        lastWorkingDate: '',
        status: 'Active'
      },
      {
        name: 'Suresh Ramesh',
        id: 'SEC-1073',
        department: 'Finance',
        designation: 'Junior Auditor',
        joiningDate: '2024-02-18',
        lastWorkingDate: '2026-07-15',
        status: 'Resigned'
      },
      {
        name: 'Priya Sundaram',
        id: 'SEC-1004',
        department: 'IT Security',
        designation: 'SOC Incident Responder',
        joiningDate: '2020-05-20',
        lastWorkingDate: '',
        status: 'Active'
      },
      {
        name: 'Karthik Rajan',
        id: 'SEC-1061',
        department: 'Business Dev',
        designation: 'Enterprise Solutions Exec',
        joiningDate: '2023-09-01',
        lastWorkingDate: '',
        status: 'Active'
      }
    ];

    // 2. Initial Credentials
    const initialCredentials = [
      {
        username: 'r.menon',
        empId: 'SEC-1088',
        name: 'Rohan Menon',
        accountType: 'Finance ERP & Core Banking',
        lastLogin: '2026-08-13 23:14:02',
        accountStatus: 'Flagged',
        mfaStatus: 'Not Enrolled',
        inactivityDays: 0,
        isGhostRisk: true
      },
      {
        username: 'a.sharma',
        empId: 'SEC-1042',
        name: 'Ananya Sharma',
        accountType: 'Cloud Infrastructure / AWS',
        lastLogin: '2026-11-20 08:30:15',
        accountStatus: 'Active',
        mfaStatus: 'Enrolled (TOTP)',
        inactivityDays: 0,
        isGhostRisk: false
      },
      {
        username: 'k.patel',
        empId: 'SEC-1055',
        name: 'Kavita Patel',
        accountType: 'Workday HRMS & Payroll',
        lastLogin: '2026-11-16 14:20:00',
        accountStatus: 'Active',
        mfaStatus: 'Not Enrolled',
        inactivityDays: 4, // 3-5 days threshold warning!
        isGhostRisk: false
      },
      {
        username: 'v.anand',
        empId: 'SEC-1019',
        name: 'Vikram Anand',
        accountType: 'ERP Logistics',
        lastLogin: '2026-11-12 11:10:45',
        accountStatus: 'Active',
        mfaStatus: 'Enrolled (TOTP)',
        inactivityDays: 8,
        isGhostRisk: false
      },
      {
        username: 's.ramesh',
        empId: 'SEC-1073',
        name: 'Suresh Ramesh',
        accountType: 'Finance Read-Only',
        lastLogin: '2026-07-15 16:50:00',
        accountStatus: 'Suspended',
        mfaStatus: 'Not Enrolled',
        inactivityDays: 128,
        isGhostRisk: true
      },
      {
        username: 'p.sundaram',
        empId: 'SEC-1004',
        name: 'Priya Sundaram',
        accountType: 'SIEM & SOC Admin Console',
        lastLogin: '2026-11-20 09:00:10',
        accountStatus: 'Active',
        mfaStatus: 'Enrolled (Hardware Key)',
        inactivityDays: 0,
        isGhostRisk: false
      }
    ];

    // 3. Initial Security Alerts (Covering all requested categories & severities)
    const initialAlerts = [
      {
        id: 1,
        title: 'Former employee account successfully authenticated after departure.',
        category: 'Login after resignation',
        severity: 'Critical',
        targetUsername: 'r.menon',
        sourceIp: '172.16.8.44 (Chennai)',
        timestamp: '2026-08-13 23:14:02',
        status: 'Pending',
        isSimulated: true,
        details: 'SIMULATED CASE: Rohan Menon officially resigned on 30 June 2026. Account successfully logged into internal finance portal on 13 August 2026 (44 days later) with password only. Ghost access confirmed.'
      },
      {
        id: 2,
        title: 'Ghost Credential Un-revoked in Finance Active Directory',
        category: 'Former employee account still active',
        severity: 'High',
        targetUsername: 's.ramesh',
        sourceIp: 'Internal Directory',
        timestamp: '2026-08-10 10:15:00',
        status: 'Pending',
        isSimulated: false,
        details: 'Departed employee Suresh Ramesh retained active financial credentials 25 days after termination.'
      },
      {
        id: 3,
        title: 'Account Dormancy Met Inactivity Threshold (4 Days)',
        category: 'Inactive credentials',
        severity: 'Medium',
        targetUsername: 'k.patel',
        sourceIp: '192.168.2.18',
        timestamp: '2026-11-19 09:00:00',
        status: 'Pending',
        isSimulated: false,
        details: 'Account k.patel reached 4 days of dormancy without login. Subject to review under 3–5 day inactivity sentinel.'
      },
      {
        id: 4,
        title: 'Sensitive Division Account Lacking Multi-Factor Token',
        category: 'MFA not enrolled',
        severity: 'Medium',
        targetUsername: 'k.patel',
        sourceIp: 'Internal HRMS',
        timestamp: '2026-11-18 14:00:00',
        status: 'Pending',
        isSimulated: false,
        details: 'HR Generalist account handling employee confidential files has not enrolled in secondary authentication.'
      },
      {
        id: 5,
        title: 'Anomalous Token Refresh via Unregistered External Subnet',
        category: 'Suspicious API activity',
        severity: 'Low',
        targetUsername: 'v.anand',
        sourceIp: '103.21.144.12',
        timestamp: '2026-11-17 03:45:12',
        status: 'Resolved',
        isSimulated: false,
        details: 'Mobile API token refresh occurred from off-premises IP during travel. Verified with field supervisor.'
      }
    ];

    // 4. Initial Approval Requests (6 Pending)
    const initialApprovals = [
      {
        id: 'REQ-301',
        targetUsername: 'v.anand',
        requestType: 'Account Reactivation',
        urgency: 'High',
        reason: 'Returning from 8-day operational field audit in Coimbatore. Requesting security lock clearance.',
        status: 'Pending',
        adminResponse: '',
        reviewedBy: ''
      },
      {
        id: 'REQ-302',
        targetUsername: 'k.patel',
        requestType: 'MFA Reset & Token Re-enrollment',
        urgency: 'Medium',
        reason: 'Replaced corporate device. Requesting new QR token for Microsoft Authenticator.',
        status: 'Pending',
        adminResponse: '',
        reviewedBy: ''
      },
      {
        id: 'REQ-303',
        targetUsername: 'a.sharma',
        requestType: 'Temporary Elevated Access',
        urgency: 'Medium',
        reason: 'Need production read-replica DB access for weekend migration rollout.',
        status: 'Pending',
        adminResponse: '',
        reviewedBy: ''
      },
      {
        id: 'REQ-304',
        targetUsername: 'r.menon',
        requestType: 'Dormancy Unfreeze',
        urgency: 'Critical',
        reason: 'Simulated post-departure access request triggered by automated anomaly detection.',
        status: 'Pending',
        adminResponse: '',
        reviewedBy: ''
      },
      {
        id: 'REQ-305',
        targetUsername: 'k.rajan',
        requestType: 'Off-hours Remote VPN Clearance',
        urgency: 'Low',
        reason: 'Client demonstration in Singapore timezone requiring non-standard login window.',
        status: 'Pending',
        adminResponse: '',
        reviewedBy: ''
      },
      {
        id: 'REQ-306',
        targetUsername: 'p.sundaram',
        requestType: 'Security Key Re-sync',
        urgency: 'Low',
        reason: 'YubiKey firmware compliance update re-authorization.',
        status: 'Pending',
        adminResponse: '',
        reviewedBy: ''
      }
    ];

    // 5. Initial Audit Logs
    const initialAudit = [
      {
        timestamp: '2026-08-13 23:16:10',
        admin: 'SYSTEM_DETECTOR',
        action: 'GHOST_ACCESS_DETECTED',
        target: 'r.menon',
        details: 'Simulated breach: Rohan Menon authenticated 44 days post-resignation from 172.16.8.44. Critical Alert #1 generated.',
        ip: '127.0.0.1'
      },
      {
        timestamp: '2026-08-10 11:00:00',
        admin: 'admin',
        action: 'ACCOUNT_SUSPEND',
        target: 's.ramesh',
        details: 'Quarantined credentials for resigned employee Suresh Ramesh.',
        ip: '192.168.1.10'
      },
      {
        timestamp: '2026-08-01 09:30:00',
        admin: 'admin',
        action: 'POLICY_UPDATE',
        target: 'SentinelEngine',
        details: 'Inactivity detection window set to 3–5 days threshold alert.',
        ip: '192.168.1.10'
      }
    ];

    localStorage.setItem(KEYS.EMPLOYEES, JSON.stringify(initialEmployees));
    localStorage.setItem(KEYS.CREDENTIALS, JSON.stringify(initialCredentials));
    localStorage.setItem(KEYS.ALERTS, JSON.stringify(initialAlerts));
    localStorage.setItem(KEYS.APPROVALS, JSON.stringify(initialApprovals));
    localStorage.setItem(KEYS.AUDIT, JSON.stringify(initialAudit));
  }

  // Populate In-Memory State
  appState.employees = JSON.parse(localStorage.getItem(KEYS.EMPLOYEES) || '[]');
  appState.credentials = JSON.parse(localStorage.getItem(KEYS.CREDENTIALS) || '[]');
  appState.alerts = JSON.parse(localStorage.getItem(KEYS.ALERTS) || '[]');
  appState.approvals = JSON.parse(localStorage.getItem(KEYS.APPROVALS) || '[]');
  appState.auditLogs = JSON.parse(localStorage.getItem(KEYS.AUDIT) || '[]');
}

function persistState() {
  localStorage.setItem(KEYS.EMPLOYEES, JSON.stringify(appState.employees));
  localStorage.setItem(KEYS.CREDENTIALS, JSON.stringify(appState.credentials));
  localStorage.setItem(KEYS.ALERTS, JSON.stringify(appState.alerts));
  localStorage.setItem(KEYS.APPROVALS, JSON.stringify(appState.approvals));
  localStorage.setItem(KEYS.AUDIT, JSON.stringify(appState.auditLogs));
}

function resetDemoData() {
  if (confirm('Reset entire demonstration dataset back to default Hackathon baseline?')) {
    loadOrSeedData(true);
    showToast('Demo data reloaded to baseline!', 'info');
    renderCurrentView();
  }
}

// ============================================================================
// AUTHENTICATION & SESSION MANAGEMENT
// ============================================================================
let selectedRoleTab = 'admin';

function setLoginRole(role) {
  selectedRoleTab = role;
  const tabAdmin = document.getElementById('tabAdmin');
  const tabEmp = document.getElementById('tabEmployee');
  const btnLabel = document.getElementById('loginBtnLabel');

  if (role === 'admin') {
    tabAdmin.classList.add('active');
    tabEmp.classList.remove('active');
    btnLabel.textContent = 'Access SOC Command Center';
  } else {
    tabEmp.classList.add('active');
    tabAdmin.classList.remove('active');
    btnLabel.textContent = 'Access Employee Portal';
  }
}

function fillCredentials(username, password, role) {
  document.getElementById('loginUsername').value = username;
  document.getElementById('loginPassword').value = password;
  setLoginRole(role);
}

function handleLoginSubmit(e) {
  e.preventDefault();
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value.trim();

  // Validate Demo Credentials
  if (username === 'admin' && password === 'Admin@2026') {
    loginSuccess({
      username: 'admin',
      role: 'admin',
      name: 'SOC Administrator',
      position: 'Lead Security Analyst',
      department: 'IT Security'
    });
  } else if (username === 'r.menon' && password === 'Rohan@1234') {
    loginSuccess({
      username: 'r.menon',
      role: 'employee',
      name: 'Rohan Menon',
      position: 'Accounts Payable Clerk',
      department: 'Finance',
      status: 'Resigned'
    });
  } else if (username === 'a.sharma' && password === 'Employee@2026') {
    loginSuccess({
      username: 'a.sharma',
      role: 'employee',
      name: 'Ananya Sharma',
      position: 'Senior DevOps Engineer',
      department: 'IT Infrastructure',
      status: 'Active'
    });
  } else {
    showToast('Invalid credentials. Use provided demo logins.', 'danger');
  }
}

function loginSuccess(user) {
  appState.currentUser = user;
  localStorage.setItem(KEYS.SESSION, JSON.stringify(user));

  // Log authentication in audit
  recordAudit(
    user.username,
    'USER_AUTHENTICATION',
    user.username,
    `Logged in as [${user.role.toUpperCase()}] from 192.168.1.5`
  );

  document.getElementById('loginSection').style.display = 'none';
  document.getElementById('appContainer').style.display = 'flex';

  updateUserInterfaceForRole();
  showToast(`Welcome back, ${user.name}!`, 'success');

  if (user.role === 'admin') {
    switchView('dashboardView');
  } else {
    switchView('employeeDashboardView');
  }
}

function checkExistingSession() {
  const stored = localStorage.getItem(KEYS.SESSION);
  if (stored) {
    try {
      const user = JSON.parse(stored);
      loginSuccess(user);
    } catch (e) {
      localStorage.removeItem(KEYS.SESSION);
    }
  }
}

function handleLogout() {
  if (appState.currentUser) {
    recordAudit(
      appState.currentUser.username,
      'USER_LOGOUT',
      appState.currentUser.username,
      'Terminated active session.'
    );
  }
  appState.currentUser = null;
  localStorage.removeItem(KEYS.SESSION);

  document.getElementById('appContainer').style.display = 'none';
  document.getElementById('loginSection').style.display = 'flex';
  showToast('Logged out securely.', 'info');
}

function updateUserInterfaceForRole() {
  const user = appState.currentUser;
  if (!user) return;

  document.getElementById('sidebarUserName').textContent = user.name;
  document.getElementById('sidebarUserRole').textContent = user.role.toUpperCase();
  document.getElementById('sidebarUserAvatar').textContent = user.username.charAt(0).toUpperCase();

  // Hide admin-only links if logged in as employee
  const adminLinks = document.querySelectorAll('.admin-only-nav');
  if (user.role === 'admin') {
    adminLinks.forEach(el => el.style.display = 'flex');
  } else {
    adminLinks.forEach(el => el.style.display = 'none');
  }
}

// ============================================================================
// VIEW NAVIGATION ROUTING
// ============================================================================
function switchView(viewId) {
  // Guard check: employee cannot access admin views
  if (appState.currentUser && appState.currentUser.role === 'employee' && viewId !== 'employeeDashboardView') {
    showToast('Access Denied: Administrator role required.', 'danger');
    return;
  }

  appState.activeView = viewId;

  // Update active state in sidebar
  document.querySelectorAll('.nav-link').forEach(link => {
    if (link.getAttribute('data-view') === viewId) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });

  // Switch view containers
  document.querySelectorAll('.app-view').forEach(view => {
    view.classList.remove('active-view');
  });
  const targetView = document.getElementById(viewId);
  if (targetView) {
    targetView.classList.add('active-view');
  }

  // Update header title
  const titles = {
    dashboardView: 'SOC Command Center',
    employeesView: 'Employee Identity Directory',
    credentialMonitoringView: 'Credential & Ghost Access Surveillance',
    alertsView: 'Threat Alerts & Incident Response',
    approvalsView: 'Administrative Clearance & Approvals',
    auditLogsView: 'Cryptographic Security Audit Logs',
    employeeDashboardView: 'Personal Identity & Credential Hub'
  };
  document.getElementById('currentViewTitle').textContent = titles[viewId] || 'SOC Command Center';

  renderCurrentView();
}

function renderCurrentView() {
  updateBadgesAndCounters();
  switch (appState.activeView) {
    case 'dashboardView':
      renderDashboardCharts();
      break;
    case 'employeesView':
      renderEmployeesTable();
      break;
    case 'credentialMonitoringView':
      renderCredentialTable();
      break;
    case 'alertsView':
      renderAlertsList();
      break;
    case 'approvalsView':
      renderApprovalsTable();
      break;
    case 'auditLogsView':
      renderAuditTable();
      break;
    case 'employeeDashboardView':
      renderEmployeeView();
      break;
  }
}

function updateBadgesAndCounters() {
  // Required numbers from specification:
  // Total Employees: 120 | Active Accounts: 95 | Inactive Accounts: 15
  // Suspicious Accounts: 10 | Critical Alerts: 4 | Pending Approvals: 6
  document.getElementById('kpiTotalEmployees').textContent = '120';
  document.getElementById('kpiActiveAccounts').textContent = '95';
  document.getElementById('kpiInactiveAccounts').textContent = '15';
  document.getElementById('kpiSuspiciousAccounts').textContent = '10';

  const pendingCritAlerts = appState.alerts.filter(a => a.severity === 'Critical' && a.status === 'Pending').length;
  document.getElementById('kpiCriticalAlerts').textContent = pendingCritAlerts || '4';
  document.getElementById('sidebarCriticalPill').textContent = pendingCritAlerts || '4';

  const pendingApprovalsCount = appState.approvals.filter(a => a.status === 'Pending').length;
  document.getElementById('kpiPendingApprovals').textContent = pendingApprovalsCount;
  document.getElementById('sidebarApprovalsPill').textContent = pendingApprovalsCount;
}

// ============================================================================
// MODULE 2: DASHBOARD CHARTS
// ============================================================================
function renderDashboardCharts() {
  if (typeof Chart === 'undefined') {
    return;
  }

  // Chart 1: Login Activity & Threat Telemetry (Line)
  const ctxActivity = document.getElementById('loginActivityChart');
  if (ctxActivity) {
    if (appState.charts.activity) {
      appState.charts.activity.destroy();
    }

    appState.charts.activity = new Chart(ctxActivity, {
      type: 'line',
      data: {
        labels: ['07 Aug', '08 Aug', '09 Aug', '10 Aug', '11 Aug', '12 Aug', '13 Aug (Incident)', 'Yesterday', 'Today'],
        datasets: [
          {
            label: 'Legitimate Authentications',
            data: [92, 95, 88, 90, 94, 91, 95, 93, 95],
            borderColor: '#8B1E3F',
            backgroundColor: 'rgba(139, 30, 63, 0.2)',
            fill: true,
            tension: 0.35,
            borderWidth: 2,
            pointBackgroundColor: '#A6244C'
          },
          {
            label: 'Ghost / Blocked Anomalies',
            data: [0, 0, 1, 0, 1, 0, 4, 1, 0],
            borderColor: '#EF4444',
            backgroundColor: 'rgba(239, 68, 68, 0.25)',
            fill: true,
            tension: 0.3,
            borderWidth: 2,
            pointBackgroundColor: '#EF4444'
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid: { color: 'rgba(255,255,255,0.05)' },
            ticks: { color: '#94A3B8', font: { family: 'JetBrains Mono', size: 10 } }
          },
          y: {
            grid: { color: 'rgba(255,255,255,0.05)' },
            ticks: { color: '#94A3B8', font: { family: 'JetBrains Mono', size: 10 } }
          }
        },
        plugins: {
          legend: { labels: { color: '#CBD5E1', font: { size: 11 } } }
        }
      }
    });
  }

  // Chart 2: Account Status Breakdown (Doughnut)
  const ctxStatus = document.getElementById('accountStatusChart');
  if (ctxStatus) {
    if (appState.charts.status) {
      appState.charts.status.destroy();
    }

    // Exact requested numbers: 95 Active, 15 Inactive, 10 Suspicious
    appState.charts.status = new Chart(ctxStatus, {
      type: 'doughnut',
      data: {
        labels: ['Active (95)', 'Inactive / Dormant (15)', 'Suspicious / Flagged (10)'],
        datasets: [{
          data: [95, 15, 10],
          backgroundColor: [
            '#10B981', // Green
            '#F59E0B', // Amber
            '#EF4444'  // Red
          ],
          borderColor: '#191923',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#CBD5E1', font: { size: 11 } } }
        },
        cutout: '65%'
      }
    });
  }
}

function toggleInvestigationPanel() {
  const panel = document.getElementById('rohanInvestigationPanel');
  if (panel.style.display === 'none') {
    panel.style.display = 'block';
  } else {
    panel.style.display = 'none';
  }
}

function quarantineRohanAccount() {
  // Update credential
  const cred = appState.credentials.find(c => c.username === 'r.menon');
  if (cred) {
    cred.accountStatus = 'Suspended';
  }
  // Update alert status
  const alert = appState.alerts.find(a => a.targetUsername === 'r.menon');
  if (alert) {
    alert.status = 'Quarantined';
  }
  persistState();

  recordAudit(
    appState.currentUser ? appState.currentUser.username : 'admin',
    'ACCOUNT_QUARANTINE',
    'r.menon',
    'Emergency quarantine enforced: Account credentials revoked and active session killed.'
  );

  const btn = document.getElementById('btnQuarantineRohan');
  if (btn) {
    btn.disabled = true;
    btn.className = 'btn btn-outline btn-sm';
    btn.innerHTML = '<i class="fas fa-check"></i> Account Quarantined & Suspended';
  }

  showToast('Account r.menon SUSPENDED immediately. Credentials revoked.', 'danger');
  updateBadgesAndCounters();
}

function approveIncidentAction(employeeName, actionTitle) {
  recordAudit(
    appState.currentUser ? appState.currentUser.username : 'admin',
    'INCIDENT_REVIEW_COMPLETED',
    employeeName,
    `Admin reviewed case study: ${actionTitle}`
  );
  showToast(`Incident action applied: ${actionTitle}`, 'success');
}

// ============================================================================
// MODULE 3: EMPLOYEE MANAGEMENT
// ============================================================================
function renderEmployeesTable() {
  const tbody = document.getElementById('employeeTableBody');
  if (!tbody) return;

  const search = (document.getElementById('employeeSearchInput')?.value || '').toLowerCase();
  const deptFilter = document.getElementById('employeeDeptFilter')?.value || '';
  const statusFilter = document.getElementById('employeeStatusFilter')?.value || '';

  const filtered = appState.employees.filter(emp => {
    const matchSearch = emp.name.toLowerCase().includes(search) ||
                        emp.id.toLowerCase().includes(search) ||
                        emp.department.toLowerCase().includes(search) ||
                        emp.designation.toLowerCase().includes(search);
    const matchDept = !deptFilter || emp.department === deptFilter;
    const matchStatus = !statusFilter || emp.status === statusFilter;
    return matchSearch && matchDept && matchStatus;
  });

  tbody.innerHTML = '';
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 24px; color: #94A3B8;">No employee identities match criteria.</td></tr>`;
    return;
  }

  filtered.forEach((emp) => {
    const originalIndex = appState.employees.indexOf(emp);
    const tr = document.createElement('tr');
    if (emp.status === 'Resigned' || emp.status === 'Terminated') {
      tr.className = 'row-flagged';
    }

    tr.innerHTML = `
      <td>
        <strong style="color: #FFF;">${emp.name}</strong>
        ${emp.name === 'Rohan Menon' ? '<span class="demo-chip-danger" style="margin-left: 6px;">INCIDENT CASE</span>' : ''}
      </td>
      <td><code>${emp.id}</code></td>
      <td>${emp.department}</td>
      <td>${emp.designation}</td>
      <td>${emp.joiningDate || 'N/A'}</td>
      <td>
        ${emp.lastWorkingDate ? `<span style="color: #F87171; font-weight: 700;">${emp.lastWorkingDate}</span>` : '<span style="color: #64748B;">N/A</span>'}
      </td>
      <td>
        <span class="badge ${emp.status === 'Active' ? 'badge-active' : emp.status === 'Resigned' ? 'badge-suspended' : 'badge-dormant'}">
          ${emp.status}
        </span>
      </td>
      <td style="text-align: right;">
        <div style="display: inline-flex; gap: 6px;">
          <button type="button" class="btn btn-outline btn-sm" onclick="openEditEmployeeModal(${originalIndex})" title="Edit">
            <i class="fas fa-pen-to-square"></i>
          </button>
          <button type="button" class="btn btn-outline-danger btn-sm" onclick="deleteEmployee(${originalIndex})" title="Delete">
            <i class="fas fa-trash-can"></i>
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function filterEmployeeTable() {
  renderEmployeesTable();
}

function toggleLwdField(statusVal, elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  if (statusVal === 'Resigned' || statusVal === 'Terminated') {
    el.style.display = 'block';
  } else {
    el.style.display = 'none';
  }
}

function openAddEmployeeModal() {
  document.getElementById('addEmployeeForm').reset();
  toggleLwdField('Active', 'addEmpLwdGroup');
  openModal('addEmployeeModal');
}

function handleAddEmployee(e) {
  e.preventDefault();
  const name = document.getElementById('addEmpName').value.trim();
  const id = document.getElementById('addEmpId').value.trim();
  const dept = document.getElementById('addEmpDept').value;
  const desig = document.getElementById('addEmpDesignation').value.trim();
  const joining = document.getElementById('addEmpJoining').value;
  const status = document.getElementById('addEmpStatus').value;
  const lwd = document.getElementById('addEmpLwd').value;

  const newEmp = {
    name,
    id,
    department: dept,
    designation: desig,
    joiningDate: joining,
    lastWorkingDate: (status === 'Resigned' || status === 'Terminated') ? lwd : '',
    status
  };

  appState.employees.unshift(newEmp);

  // Also provision into credentials table
  const username = name.toLowerCase().replace(/[^a-z0-9]/g, '.');
  appState.credentials.unshift({
    username,
    empId: id,
    name,
    accountType: `${dept} Standard`,
    lastLogin: 'Never Authenticated',
    accountStatus: status === 'Active' ? 'Active' : 'Suspended',
    mfaStatus: 'Not Enrolled',
    inactivityDays: 0,
    isGhostRisk: status === 'Resigned'
  });

  persistState();
  closeModal('addEmployeeModal');

  recordAudit(
    appState.currentUser ? appState.currentUser.username : 'admin',
    'EMPLOYEE_PROVISIONED',
    name,
    `Added identity ${id} (${desig}, ${dept}) with status: ${status}`
  );

  showToast(`Employee ${name} added successfully!`, 'success');
  renderEmployeesTable();
}

function openEditEmployeeModal(index) {
  const emp = appState.employees[index];
  if (!emp) return;

  document.getElementById('editEmpIndex').value = index;
  document.getElementById('editEmpName').value = emp.name;
  document.getElementById('editEmpId').value = emp.id;
  document.getElementById('editEmpDept').value = emp.department;
  document.getElementById('editEmpDesignation').value = emp.designation;
  document.getElementById('editEmpStatus').value = emp.status;
  document.getElementById('editEmpLwd').value = emp.lastWorkingDate || '';

  toggleLwdField(emp.status, 'editEmpLwdGroup');
  openModal('editEmployeeModal');
}

function handleEditEmployee(e) {
  e.preventDefault();
  const index = parseInt(document.getElementById('editEmpIndex').value, 10);
  const emp = appState.employees[index];
  if (!emp) return;

  emp.name = document.getElementById('editEmpName').value.trim();
  emp.department = document.getElementById('editEmpDept').value;
  emp.designation = document.getElementById('editEmpDesignation').value.trim();
  emp.status = document.getElementById('editEmpStatus').value;
  emp.lastWorkingDate = (emp.status === 'Resigned' || emp.status === 'Terminated') ? document.getElementById('editEmpLwd').value : '';

  persistState();
  closeModal('editEmployeeModal');

  recordAudit(
    appState.currentUser ? appState.currentUser.username : 'admin',
    'EMPLOYEE_UPDATED',
    emp.name,
    `Updated status to ${emp.status}, LWD: ${emp.lastWorkingDate || 'N/A'}`
  );

  showToast(`Updated record for ${emp.name}`, 'success');
  renderEmployeesTable();
}

function deleteEmployee(index) {
  const emp = appState.employees[index];
  if (!emp) return;

  if (confirm(`Permanently remove employee record "${emp.name}" (${emp.id}) from system?`)) {
    const deletedName = emp.name;
    appState.employees.splice(index, 1);
    persistState();

    recordAudit(
      appState.currentUser ? appState.currentUser.username : 'admin',
      'EMPLOYEE_DELETED',
      deletedName,
      `Purged employee identity ${emp.id} from directory.`
    );

    showToast(`Removed employee ${deletedName}`, 'info');
    renderEmployeesTable();
  }
}

// ============================================================================
// MODULE 4: CREDENTIAL MONITORING
// ============================================================================
function renderCredentialTable() {
  const tbody = document.getElementById('credentialTableBody');
  if (!tbody) return;

  tbody.innerHTML = '';
  appState.credentials.forEach(cred => {
    const tr = document.createElement('tr');
    if (cred.accountStatus === 'Flagged') {
      tr.className = 'row-flagged';
    } else if (cred.inactivityDays >= 3 && cred.accountStatus !== 'Suspended') {
      tr.className = 'row-dormant';
    }

    tr.innerHTML = `
      <td>
        <strong style="color: #FFF;">${cred.username}</strong>
        ${cred.username === 'r.menon' ? '<span class="demo-chip-danger" style="margin-left: 6px;">GHOST ACCESS</span>' : ''}
        <div style="font-size: 11px; color: #94A3B8;">${cred.name}</div>
      </td>
      <td><code>${cred.empId}</code></td>
      <td><span style="font-size: 12px; color: #CBD5E1;">${cred.accountType}</span></td>
      <td>
        <span style="font-family: var(--font-mono); font-size: 12px;">${cred.lastLogin}</span>
      </td>
      <td>
        <span class="badge ${cred.mfaStatus.includes('Enrolled') ? 'badge-mfa-yes' : 'badge-mfa-no'}">
          ${cred.mfaStatus}
        </span>
      </td>
      <td>
        <strong style="color: ${cred.inactivityDays >= 3 ? '#FBBF24' : '#94A3B8'}; font-family: var(--font-mono);">
          ${cred.inactivityDays} Days
        </strong>
        ${cred.inactivityDays >= 3 && cred.inactivityDays <= 5 ? '<span class="badge badge-dormant" style="font-size: 9px; padding: 1px 5px; margin-left: 4px;">3-5d Warning</span>' : ''}
      </td>
      <td>
        <span class="badge ${cred.accountStatus === 'Active' ? 'badge-active' : cred.accountStatus === 'Suspended' ? 'badge-suspended' : 'badge-flagged'}">
          ${cred.accountStatus}
        </span>
      </td>
      <td style="text-align: right;">
        ${cred.accountStatus !== 'Suspended' ? `
          <button type="button" class="btn btn-outline-danger btn-sm" onclick="promptSuspend('${cred.username}')">
            <i class="fas fa-ban"></i> Suspend
          </button>
        ` : `
          <button type="button" class="btn btn-primary btn-sm" onclick="promptReactivate('${cred.username}')">
            <i class="fas fa-rotate-left"></i> Reactivate
          </button>
        `}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function promptSuspend(username) {
  openDecisionModal(
    'ACCOUNT_SUSPEND',
    username,
    `Suspending account "${username}" will immediately revoke active access tokens and prevent further authentications.`,
    'Suspend Account',
    'btn btn-danger'
  );
}

function promptReactivate(username) {
  openDecisionModal(
    'ACCOUNT_REACTIVATE',
    username,
    `Reactivate credentials and restore normal access permissions for account "${username}".`,
    'Reactivate Account',
    'btn btn-primary'
  );
}

// ============================================================================
// MODULE 5: SECURITY ALERTS
// ============================================================================
let activeAlertFilter = 'All';

function filterAlerts(severity) {
  activeAlertFilter = severity;
  document.querySelectorAll('.alert-filter-btn').forEach(btn => {
    if (btn.textContent.trim().includes(severity)) {
      btn.className = 'btn btn-primary btn-sm alert-filter-btn active';
    } else {
      btn.className = 'btn btn-outline btn-sm alert-filter-btn';
    }
  });
  renderAlertsList();
}

function renderAlertsList() {
  const container = document.getElementById('alertsContainer');
  if (!container) return;

  const filtered = appState.alerts.filter(a => {
    return activeAlertFilter === 'All' || a.severity === activeAlertFilter;
  });

  container.innerHTML = '';
  if (filtered.length === 0) {
    container.innerHTML = '<div style="padding: 24px; text-align: center; color: #94A3B8;">No alerts match filter.</div>';
    return;
  }

  filtered.forEach(alert => {
    const card = document.createElement('div');
    card.style.background = alert.severity === 'Critical' ? 'linear-gradient(135deg, rgba(239, 68, 68, 0.12) 0%, #191923 100%)' : '#191923';
    card.style.border = alert.severity === 'Critical' ? '1px solid #EF4444' : '1px solid rgba(255, 255, 255, 0.08)';
    card.style.borderRadius = '8px';
    card.style.padding = '16px';

    card.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">
        <div>
          <span class="badge-severity ${alert.severity === 'Critical' ? 'sev-critical' : alert.severity === 'High' ? 'sev-high' : alert.severity === 'Medium' ? 'sev-medium' : 'sev-low'}">
            ${alert.severity}
          </span>
          <span class="demo-chip" style="margin-left: 6px;">${alert.category}</span>
          ${alert.isSimulated ? '<span class="demo-chip-simulated" style="margin-left: 6px;">SIMULATED DEMO CASE</span>' : ''}
          <strong style="color: #FFF; font-size: 14px; margin-left: 8px;">${alert.title}</strong>
        </div>
        <span style="font-size: 11px; font-family: var(--font-mono); color: #94A3B8;">
          <i class="fas fa-clock"></i> ${alert.timestamp}
        </span>
      </div>

      <p style="font-size: 13px; color: #CBD5E1; line-height: 1.5; margin-bottom: 12px;">
        ${alert.details}
      </p>

      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
        <div style="font-size: 11.5px; font-family: var(--font-mono); color: #94A3B8;">
          Target Account: <strong style="color: #FFF;">${alert.targetUsername}</strong> &bull; Origin: <code>${alert.sourceIp}</code> &bull; Status: <strong style="color: ${alert.status === 'Resolved' ? '#34D399' : '#F87171'};">${alert.status}</strong>
        </div>

        <div style="display: flex; gap: 8px;">
          ${alert.status === 'Pending' ? `
            <button type="button" class="btn btn-outline-danger btn-sm" onclick="promptSuspend('${alert.targetUsername}')">
              <i class="fas fa-ban"></i> Suspend User
            </button>
            <button type="button" class="btn btn-primary btn-sm" onclick="resolveAlert(${alert.id})">
              <i class="fas fa-check"></i> Mark Resolved
            </button>
          ` : `
            <span style="font-size: 11px; color: #64748B; font-family: var(--font-mono);">INCIDENT CLOSED</span>
          `}
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

function resolveAlert(alertId) {
  const alert = appState.alerts.find(a => a.id === alertId);
  if (!alert) return;

  alert.status = 'Resolved';
  persistState();

  recordAudit(
    appState.currentUser ? appState.currentUser.username : 'admin',
    'ALERT_RESOLVED',
    alert.targetUsername,
    `Resolved alert #${alertId}: ${alert.title}`
  );

  showToast(`Alert #${alertId} marked as Resolved!`, 'success');
  renderAlertsList();
  updateBadgesAndCounters();
}

// ============================================================================
// MODULE 6: APPROVAL SYSTEM
// ============================================================================
let activeApprovalFilter = 'All';

function filterApprovals(status) {
  activeApprovalFilter = status;
  document.querySelectorAll('.approval-filter-btn').forEach(btn => {
    if (btn.textContent.trim().includes(status)) {
      btn.className = 'btn btn-primary btn-sm approval-filter-btn active';
    } else {
      btn.className = 'btn btn-outline btn-sm approval-filter-btn';
    }
  });
  renderApprovalsTable();
}

function renderApprovalsTable() {
  const tbody = document.getElementById('approvalsTableBody');
  if (!tbody) return;

  const filtered = appState.approvals.filter(a => {
    return activeApprovalFilter === 'All' || a.status === activeApprovalFilter;
  });

  tbody.innerHTML = '';
  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 24px; color: #94A3B8;">No requests in this queue.</td></tr>`;
    return;
  }

  filtered.forEach(req => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${req.id}</code></td>
      <td><strong style="color: #FFF;">${req.targetUsername}</strong></td>
      <td>${req.requestType}</td>
      <td>
        <span class="badge-severity ${req.urgency === 'Critical' ? 'sev-critical' : req.urgency === 'High' ? 'sev-high' : 'sev-medium'}">
          ${req.urgency}
        </span>
      </td>
      <td style="max-width: 280px; font-size: 12px; color: #CBD5E1;">${req.reason}</td>
      <td>
        <span class="badge ${req.status === 'Approved' ? 'badge-active' : req.status === 'Rejected' ? 'badge-suspended' : 'badge-dormant'}">
          ${req.status}
        </span>
      </td>
      <td style="font-size: 11.5px; color: #94A3B8;">
        ${req.adminResponse ? `${req.adminResponse} (${req.reviewedBy})` : '<em>Awaiting review</em>'}
      </td>
      <td style="text-align: right;">
        ${req.status === 'Pending' ? `
          <div style="display: inline-flex; gap: 6px;">
            <button type="button" class="btn btn-primary btn-sm" onclick="promptApprove('${req.id}')">
              <i class="fas fa-check"></i> Approve
            </button>
            <button type="button" class="btn btn-outline-danger btn-sm" onclick="promptReject('${req.id}')">
              <i class="fas fa-xmark"></i> Reject
            </button>
          </div>
        ` : `
          <span style="font-size: 11px; color: #64748B;">DECIDED</span>
        `}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function promptApprove(reqId) {
  openDecisionModal(
    'APPROVAL_APPROVE',
    reqId,
    `Authorize request "${reqId}". Enter administrative directives or confirmation remarks:`,
    'Authorize & Approve',
    'btn btn-primary'
  );
}

function promptReject(reqId) {
  openDecisionModal(
    'APPROVAL_REJECT',
    reqId,
    `Reject request "${reqId}". Enter mandatory security reason for denial:`,
    'Confirm Rejection',
    'btn btn-danger'
  );
}

// ============================================================================
// DECISION & REASON MODAL HANDLER
// ============================================================================
function openDecisionModal(actionType, targetId, promptText, btnText, btnClass) {
  document.getElementById('decisionAction').value = actionType;
  document.getElementById('decisionTargetId').value = targetId;
  document.getElementById('decisionModalPrompt').textContent = promptText;
  document.getElementById('decisionReasonText').value = '';

  const btn = document.getElementById('decisionSubmitBtn');
  btn.textContent = btnText;
  btn.className = btnClass;

  openModal('decisionReasonModal');
}

function handleDecisionSubmit(e) {
  e.preventDefault();
  const actionType = document.getElementById('decisionAction').value;
  const targetId = document.getElementById('decisionTargetId').value;
  const reason = document.getElementById('decisionReasonText').value.trim();
  const adminName = appState.currentUser ? appState.currentUser.username : 'admin';

  closeModal('decisionReasonModal');

  switch (actionType) {
    case 'ACCOUNT_SUSPEND': {
      const cred = appState.credentials.find(c => c.username === targetId);
      if (cred) cred.accountStatus = 'Suspended';
      recordAudit(adminName, 'ACCOUNT_SUSPENDED', targetId, `Reason: ${reason}`);
      showToast(`Account ${targetId} SUSPENDED!`, 'danger');
      renderCredentialTable();
      break;
    }
    case 'ACCOUNT_REACTIVATE': {
      const cred = appState.credentials.find(c => c.username === targetId);
      if (cred) cred.accountStatus = 'Active';
      recordAudit(adminName, 'ACCOUNT_REACTIVATED', targetId, `Clearance: ${reason}`);
      showToast(`Account ${targetId} REACTIVATED!`, 'success');
      renderCredentialTable();
      break;
    }
    case 'APPROVAL_APPROVE': {
      const req = appState.approvals.find(r => r.id === targetId);
      if (req) {
        req.status = 'Approved';
        req.adminResponse = reason;
        req.reviewedBy = adminName;
        // If it was reactivation, reactivate user
        if (req.requestType === 'Account Reactivation') {
          const cred = appState.credentials.find(c => c.username === req.targetUsername);
          if (cred) cred.accountStatus = 'Active';
        }
      }
      recordAudit(adminName, 'REQUEST_APPROVED', targetId, `Approved with note: ${reason}`);
      showToast(`Request ${targetId} APPROVED!`, 'success');
      renderApprovalsTable();
      break;
    }
    case 'APPROVAL_REJECT': {
      const req = appState.approvals.find(r => r.id === targetId);
      if (req) {
        req.status = 'Rejected';
        req.adminResponse = reason;
        req.reviewedBy = adminName;
      }
      recordAudit(adminName, 'REQUEST_REJECTED', targetId, `Denied reason: ${reason}`);
      showToast(`Request ${targetId} REJECTED!`, 'info');
      renderApprovalsTable();
      break;
    }
  }

  persistState();
  updateBadgesAndCounters();
}

// ============================================================================
// MODULE 7: AUDIT LOGS
// ============================================================================
function recordAudit(admin, action, target, details) {
  const now = new Date();
  const timestamp = now.toISOString().replace('T', ' ').slice(0, 19);

  const entry = {
    timestamp,
    admin,
    action,
    target,
    details,
    ip: '192.168.1.5'
  };

  appState.auditLogs.unshift(entry);
  persistState();
}

function renderAuditTable() {
  const tbody = document.getElementById('auditTableBody');
  if (!tbody) return;

  const search = (document.getElementById('auditSearchInput')?.value || '').toLowerCase();
  const filtered = appState.auditLogs.filter(log => {
    return log.action.toLowerCase().includes(search) ||
           log.target.toLowerCase().includes(search) ||
           log.admin.toLowerCase().includes(search) ||
           log.details.toLowerCase().includes(search);
  });

  tbody.innerHTML = '';
  filtered.forEach(log => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${log.timestamp}</code></td>
      <td><strong>${log.admin}</strong></td>
      <td><span class="badge badge-active" style="background: rgba(139,30,63,0.3); color: #FECDD3; border-color: #8B1E3F;">${log.action}</span></td>
      <td><strong>${log.target}</strong></td>
      <td style="max-width: 320px; font-size: 12px; color: #CBD5E1;">${log.details}</td>
      <td><code>${log.ip}</code></td>
    `;
    tbody.appendChild(tr);
  });
}

function filterAuditTable() {
  renderAuditTable();
}

function exportAuditLogsCSV() {
  let csv = 'Timestamp,Admin,Action,Target,Details,IP\n';
  appState.auditLogs.forEach(l => {
    csv += `"${l.timestamp}","${l.admin}","${l.action}","${l.target}","${l.details.replace(/"/g, '""')}","${l.ip}"\n`;
  });

  const blob = new Blob([csv], { type: 'text/csv' });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.setAttribute('href', url);
  a.setAttribute('download', `shadow_preventer_audit_${Date.now()}.csv`);
  a.click();
  showToast('Audit trail exported as CSV!', 'success');
}

// ============================================================================
// MODULE 8: EMPLOYEE DASHBOARD VIEW
// ============================================================================
function renderEmployeeView() {
  const user = appState.currentUser;
  if (!user) return;

  const cred = appState.credentials.find(c => c.username === user.username) || {
    accountStatus: 'Active',
    mfaStatus: 'Enrolled (TOTP)',
    inactivityDays: 0
  };

  document.getElementById('empViewPosition').textContent = user.position || 'Employee';
  document.getElementById('empViewAccountStatus').textContent = cred.accountStatus;
  document.getElementById('empViewMfaStatus').textContent = cred.mfaStatus;
  document.getElementById('empViewInactivity').textContent = `${cred.inactivityDays} Days`;

  // Render personal login history
  const tbody = document.getElementById('empLoginHistoryBody');
  if (tbody) {
    tbody.innerHTML = '';
    const personalHistory = [
      { time: 'Today 08:30:15', ip: '192.168.1.45', location: 'Chennai HQ', method: 'Password + MFA', status: 'Success' },
      { time: 'Yesterday 09:12:00', ip: '192.168.1.45', location: 'Chennai HQ', method: 'Password + MFA', status: 'Success' },
      { time: '18 Nov 2026 14:22:18', ip: '192.168.1.45', location: 'Chennai HQ', method: 'Password + MFA', status: 'Success' },
      { time: '17 Nov 2026 11:05:40', ip: '103.21.144.10', location: 'Bangalore Remote', method: 'Password + MFA', status: 'Success' }
    ];

    if (user.username === 'r.menon') {
      personalHistory.unshift({
        time: '13 Aug 2026 23:14:02',
        ip: '172.16.8.44',
        location: 'Chennai',
        method: 'Password only',
        status: 'Success (Compromised)'
      });
    }

    personalHistory.forEach(hist => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${hist.time}</code></td>
        <td><code>${hist.ip}</code></td>
        <td>${hist.location}</td>
        <td>${hist.method}</td>
        <td>
          <span class="badge ${hist.status.includes('Success') ? 'badge-active' : 'badge-suspended'}">
            ${hist.status}
          </span>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }
}

function handleEmpRequestSubmit(e) {
  e.preventDefault();
  const type = document.getElementById('empReqType').value;
  const urgency = document.getElementById('empReqUrgency').value;
  const reason = document.getElementById('empReqReason').value.trim();
  const user = appState.currentUser;

  const newId = `REQ-${300 + appState.approvals.length + 1}`;
  appState.approvals.unshift({
    id: newId,
    targetUsername: user.username,
    requestType: type,
    urgency,
    reason,
    status: 'Pending',
    adminResponse: '',
    reviewedBy: ''
  });

  persistState();
  recordAudit(user.username, 'REQUEST_SUBMITTED', user.username, `Submitted ${type} (${urgency}): ${reason}`);

  showToast('Security clearance request dispatched to SOC!', 'success');
  document.getElementById('empRequestForm').reset();
  updateBadgesAndCounters();
}

// ============================================================================
// GLOBAL MODAL CONTROLLERS & TOASTS
// ============================================================================
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add('open');
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove('open');
}

function showToast(message, type = 'info') {
  const shelf = document.getElementById('toast-shelf');
  if (!shelf) return;

  const toast = document.createElement('div');
  toast.className = `toast-message toast-${type}`;
  const icon = type === 'danger' ? 'triangle-exclamation' : type === 'success' ? 'check-circle' : 'info-circle';
  toast.innerHTML = `<i class="fas fa-${icon}"></i> <span>${message}</span>`;

  shelf.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(40px)';
    setTimeout(() => toast.remove(), 400);
  }, 4000);
}

function toggleSidebarMenu() {
  const sidebar = document.querySelector('.sidebar');
  if (sidebar) sidebar.classList.toggle('mobile-open');
}
