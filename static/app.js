/**
 * app.js
 * Global utility functions and event handlers for the password manager UI.
 */

// ============================================================================
// Theme Toggle & Navigation Helpers
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    // Theme Toggle Handler
    const themeToggleBtn = document.getElementById('themeToggle');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', function() {
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }

    // Sidebar Mobile Toggle Handler
    const sidebarToggleBtn = document.getElementById('sidebarToggle');
    const appSidebar = document.getElementById('appSidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');

    if (sidebarToggleBtn && appSidebar && sidebarOverlay) {
        function toggleSidebar() {
            appSidebar.classList.toggle('show');
            sidebarOverlay.classList.toggle('show');
        }

        sidebarToggleBtn.addEventListener('click', toggleSidebar);
        sidebarOverlay.addEventListener('click', toggleSidebar);
    }

    // Global Logout Button Handler
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async function() {
            if (!confirm('Are you sure you want to logout?')) return;
            
            try {
                const response = await fetch('/api/logout', { method: 'POST' });
                if (response.ok) {
                    showAlert('Logged out. Redirecting...', 'success');
                    setTimeout(() => window.location.href = '/', 1500);
                } else {
                    showAlert('Failed to logout', 'danger');
                }
            } catch (error) {
                showAlert('Error: ' + error.message, 'danger');
            }
        });
    }
});

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Display an alert/toast message to the user
 */
function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alertContainer');
    if (!alertContainer) return;
    
    const alertId = 'alert-' + Date.now();
    const alertHTML = `
        <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show mb-3" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    alertContainer.insertAdjacentHTML('beforeend', alertHTML);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        const alert = document.getElementById(alertId);
        if (alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }
    }, 5000);
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(element) {
    const text = element.value || element.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showAlert('Copied to clipboard!', 'success');
    }).catch(() => {
        showAlert('Failed to copy to clipboard', 'danger');
    });
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Display password strength feedback
 */
function displayStrength(strength, elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const label = strength.label || 'Unknown';
    const score = strength.score || 0;
    const maxScore = strength.max_score || 6;
    const entropy = strength.entropy_bits || 0;
    const feedback = strength.feedback || [];
    
    const percentage = (score / maxScore) * 100;
    const strengthClass = getStrengthClass(label);
    
    let html = `
        <div class="d-flex justify-content-between align-items-center mb-2">
            <span><strong>Strength:</strong> ${escapeHtml(label)}</span>
            <span class="small text-muted">~${Math.round(entropy)} bits</span>
        </div>
        <div class="progress mb-2" style="height: 10px;">
            <div class="progress-bar ${strengthClass}" role="progressbar" style="width: ${percentage}%"></div>
        </div>
    `;
    
    if (feedback.length > 0) {
        html += '<div class="small mt-2">';
        feedback.forEach(note => {
            html += `<div class="text-secondary">• ${escapeHtml(note)}</div>`;
        });
        html += '</div>';
    }
    
    element.innerHTML = html;
}

/**
 * Get Bootstrap color class based on password strength
 */
function getStrengthClass(label) {
    const classMap = {
        'Very Weak': 'bg-danger',
        'Weak': 'bg-warning text-dark',
        'Fair': 'bg-info',
        'Good': 'bg-primary',
        'Strong': 'bg-success',
        'Very Strong': 'bg-success',
        'Excellent': 'bg-success'
    };
    return classMap[label] || 'bg-secondary';
}
