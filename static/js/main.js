/**
 * SHADOW PREVENTER - CORE JAVASCRIPT UTILITIES
 * Saveetha Engineering College - Crimathon
 */

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initFlashDismiss();
  initModalListeners();
});

// Real-time digital security clock
function initClock() {
  const clockEl = document.getElementById('terminal-clock-display');
  if (!clockEl) return;

  function update() {
    const now = new Date();
    const utcHours = String(now.getUTCHours()).padStart(2, '0');
    const utcMins = String(now.getUTCMinutes()).padStart(2, '0');
    const utcSecs = String(now.getUTCSeconds()).padStart(2, '0');
    const localStr = now.toLocaleTimeString();
    clockEl.innerHTML = `<i class="fas fa-clock"></i> <span>${localStr}</span> <small style="color: #64748b; margin-left: 6px;">[UTC ${utcHours}:${utcMins}:${utcSecs}]</small>`;
  }

  update();
  setInterval(update, 1000);
}

// Auto dismiss flash alerts
function initFlashDismiss() {
  const alerts = document.querySelectorAll('.cyber-alert');
  alerts.forEach(alert => {
    setTimeout(() => {
      alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
      alert.style.opacity = '0';
      alert.style.transform = 'translateY(-10px)';
      setTimeout(() => alert.remove(), 500);
    }, 6000);
  });
}

// Global Modal handlers
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('active');
    document.body.style.overflow = '';
  }
}

function initModalListeners() {
  // Close modal when clicking on overlay background
  document.querySelectorAll('.modal-overlay').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        closeModal(modal.id);
      }
    });
  });

  // ESC key closes any open modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-overlay.active').forEach(modal => {
        closeModal(modal.id);
      });
    }
  });
}

// Mobile sidebar toggle
function toggleSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (sidebar) {
    sidebar.classList.toggle('open');
  }
}

// Dynamic Action Confirmation Modal
function confirmPrompt(actionTitle, actionText, confirmBtnText, formToSubmit, isDanger = true) {
  const modal = document.getElementById('globalConfirmModal');
  if (!modal) {
    if (confirm(actionText)) {
      formToSubmit.submit();
    }
    return;
  }

  document.getElementById('confirmModalTitle').textContent = actionTitle;
  document.getElementById('confirmModalText').textContent = actionText;
  const btn = document.getElementById('confirmModalSubmitBtn');
  btn.textContent = confirmBtnText;
  
  if (isDanger) {
    btn.className = 'btn-cyber btn-danger';
  } else {
    btn.className = 'btn-cyber btn-maroon';
  }

  btn.onclick = () => {
    formToSubmit.submit();
  };

  openModal('globalConfirmModal');
}

// Toast notification helper
function showToast(message, type = 'info') {
  let toastContainer = document.getElementById('cyber-toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'cyber-toast-container';
    toastContainer.style.position = 'fixed';
    toastContainer.style.top = '20px';
    toastContainer.style.right = '20px';
    toastContainer.style.zIndex = '9999';
    toastContainer.style.display = 'flex';
    toastContainer.style.flexDirection = 'column';
    toastContainer.style.gap = '10px';
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement('div');
  const bg = type === 'danger' ? 'rgba(239, 68, 68, 0.95)' : type === 'success' ? 'rgba(16, 185, 129, 0.95)' : 'rgba(139, 30, 63, 0.95)';
  toast.style.background = bg;
  toast.style.color = '#ffffff';
  toast.style.padding = '12px 20px';
  toast.style.borderRadius = '8px';
  toast.style.boxShadow = '0 6px 20px rgba(0,0,0,0.5)';
  toast.style.fontSize = '13px';
  toast.style.fontFamily = 'var(--font-sans)';
  toast.style.fontWeight = '600';
  toast.style.display = 'flex';
  toast.style.alignItems = 'center';
  toast.style.gap = '10px';
  toast.style.animation = 'slideDown 0.3s ease';
  
  const icon = type === 'danger' ? 'exclamation-triangle' : type === 'success' ? 'check-circle' : 'info-circle';
  toast.innerHTML = `<i class="fas fa-${icon}"></i> <span>${message}</span>`;
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px)';
    setTimeout(() => toast.remove(), 400);
  }, 4000);
}
