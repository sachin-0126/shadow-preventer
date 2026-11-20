/**
 * SHADOW PREVENTER - ADMIN DASHBOARD & CHART.JS INTEGRATION
 * Saveetha Engineering College - Crimathon Project
 */

document.addEventListener('DOMContentLoaded', () => {
  if (typeof Chart !== 'undefined') {
    initSeverityChart();
    initTelemetryChart();
    initDepartmentChart();
    initMfaChart();
  }
});

// 1. Alert Severity Breakdown (Doughnut)
function initSeverityChart() {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;

  const critical = parseInt(ctx.dataset.critical || '0', 10);
  const high = parseInt(ctx.dataset.high || '0', 10);
  const medium = parseInt(ctx.dataset.medium || '0', 10);
  const low = parseInt(ctx.dataset.low || '0', 10);

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High Risk', 'Medium Risk', 'Low Advisory'],
      datasets: [{
        data: [critical, high, medium, low],
        backgroundColor: [
          '#ef4444', // Red Alert
          '#ea580c', // High Orange
          '#f59e0b', // Medium Amber
          '#3b82f6'  // Low Blue
        ],
        borderColor: '#141722',
        borderWidth: 3,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          backgroundColor: '#0f1118',
          titleColor: '#fff',
          bodyColor: '#e2e8f0',
          borderColor: '#8B1E3F',
          borderWidth: 1,
          padding: 10
        }
      }
    }
  });
}

// 2. 7-Day Activity & Threat Telemetry (Line/Bar combination)
function initTelemetryChart() {
  const ctx = document.getElementById('telemetryChart');
  if (!ctx) return;

  new Chart(ctx, {
    type: 'line',
    data: {
      labels: ['D-6', 'D-5', 'D-4', 'D-3', 'D-2', 'Yesterday', 'Today'],
      datasets: [
        {
          label: 'Authorized Logins',
          data: [42, 38, 45, 30, 48, 52, 39],
          borderColor: '#8B1E3F',
          backgroundColor: 'rgba(139, 30, 63, 0.15)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointBackgroundColor: '#ab254e',
          pointBorderColor: '#fff',
          pointRadius: 4
        },
        {
          label: 'Anomalous / Blocked Access',
          data: [0, 1, 0, 2, 0, 1, 3],
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.25)',
          fill: true,
          tension: 0.3,
          borderWidth: 2,
          pointBackgroundColor: '#ef4444',
          pointBorderColor: '#fff',
          pointRadius: 5
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: {
            color: 'rgba(255, 255, 255, 0.05)'
          },
          ticks: {
            color: '#94a3b8',
            font: { family: 'JetBrains Mono, monospace', size: 11 }
          }
        },
        y: {
          grid: {
            color: 'rgba(255, 255, 255, 0.05)'
          },
          ticks: {
            color: '#94a3b8',
            font: { family: 'JetBrains Mono, monospace', size: 11 }
          }
        }
      },
      plugins: {
        legend: {
          labels: {
            color: '#cbd5e1',
            font: { family: 'Inter, sans-serif', size: 12 }
          }
        },
        tooltip: {
          backgroundColor: '#0f1118',
          titleColor: '#fff',
          bodyColor: '#e2e8f0',
          borderColor: '#8B1E3F',
          borderWidth: 1,
          padding: 10
        }
      }
    }
  });
}

// 3. Department Risk Breakdown (Horizontal Bar)
function initDepartmentChart() {
  const ctx = document.getElementById('deptChart');
  if (!ctx) return;

  const labels = JSON.parse(ctx.dataset.labels || '[]');
  const counts = JSON.parse(ctx.dataset.counts || '[]');

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels.length ? labels : ['Finance', 'IT Security', 'IT Infra', 'HR', 'Operations', 'Business Dev'],
      datasets: [{
        label: 'Monitored Accounts',
        data: counts.length ? counts : [2, 2, 1, 1, 1, 1],
        backgroundColor: [
          '#ef4444', // Finance (High risk / Rohan Menon)
          '#8B1E3F', // IT Security
          '#3b82f6', // IT Infra
          '#f59e0b', // HR
          '#10b981', // Operations
          '#8b5cf6'  // Business Dev
        ],
        borderRadius: 6
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#94a3b8', stepSize: 1 }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#e2e8f0', font: { weight: '600' } }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0f1118',
          borderColor: '#8B1E3F',
          borderWidth: 1
        }
      }
    }
  });
}

// 4. MFA Adoption Ratio (Pie)
function initMfaChart() {
  const ctx = document.getElementById('mfaChart');
  if (!ctx) return;

  const enrolled = parseInt(ctx.dataset.enrolled || '0', 10);
  const notEnrolled = parseInt(ctx.dataset.notEnrolled || '0', 10);

  new Chart(ctx, {
    type: 'pie',
    data: {
      labels: ['MFA Enrolled', 'Unprotected (Password Only)'],
      datasets: [{
        data: [enrolled, notEnrolled],
        backgroundColor: [
          '#10b981', // Enrolled Green
          '#ef4444'  // Unenrolled Red
        ],
        borderColor: '#141722',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#cbd5e1', padding: 12 }
        }
      }
    }
  });
}

// Manual Deep Threat Scan Trigger
async function triggerDeepScan(csrfToken) {
  const btn = document.getElementById('btnTriggerScan');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning System Telemetry...';
  }

  showToast('Initiating real-time credential integrity and shadow account scan...', 'info');

  try {
    const response = await fetch('/admin/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      }
    });

    const data = await response.json();
    if (data.success) {
      showToast(data.message, 'success');
      setTimeout(() => {
        window.location.reload();
      }, 1200);
    } else {
      showToast('Scan completed with policy exceptions.', 'danger');
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-shield-virus"></i> Run Security Scan';
      }
    }
  } catch (err) {
    console.error(err);
    showToast('Failed to connect to scan engine API.', 'danger');
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-shield-virus"></i> Run Security Scan';
    }
  }
}
