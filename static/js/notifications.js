
// Real-time notification system
class NotificationManager {
    constructor() {
        this.init();
    }

    init() {
        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }

        // Initialize toast container
        this.createToastContainer();
        
        // Setup WebSocket for real-time notifications (if available)
        this.setupWebSocket();
    }

    createToastContainer() {
        if (!document.querySelector('.toast-container')) {
            const container = document.createElement('div');
            container.className = 'toast-container position-fixed top-0 end-0 p-3';
            container.style.zIndex = '1055';
            document.body.appendChild(container);
        }
    }

    showToast(message, type = 'info', duration = 5000) {
        const toastContainer = document.querySelector('.toast-container');
        const toastId = 'toast-' + Date.now();
        
        const toastHTML = `
            <div id="${toastId}" class="toast align-items-center text-bg-${type} border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas ${this.getIconForType(type)} me-2"></i>
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `;
        
        toastContainer.insertAdjacentHTML('beforeend', toastHTML);
        
        const toastElement = document.getElementById(toastId);
        const toast = new bootstrap.Toast(toastElement, {
            autohide: true,
            delay: duration
        });
        
        toast.show();
        
        // Clean up after toast is hidden
        toastElement.addEventListener('hidden.bs.toast', () => {
            toastElement.remove();
        });
    }

    getIconForType(type) {
        const icons = {
            'success': 'fa-check-circle',
            'danger': 'fa-exclamation-triangle',
            'warning': 'fa-exclamation-circle',
            'info': 'fa-info-circle',
            'primary': 'fa-info-circle'
        };
        return icons[type] || 'fa-info-circle';
    }

    showBrowserNotification(title, message, type = 'info') {
        if ('Notification' in window && Notification.permission === 'granted') {
            const notification = new Notification(title, {
                body: message,
                icon: '/static/images/favicon.ico',
                badge: '/static/images/favicon.ico',
                tag: 'phishguard-alert'
            });

            // Auto-close after 5 seconds
            setTimeout(() => {
                notification.close();
            }, 5000);
        }
    }

    notifyThreatDetected(scanType, threatLevel, details) {
        const messages = {
            'phishing': 'High-risk phishing attempt detected!',
            'suspicious': 'Suspicious content detected - please review.',
            'safe': 'Content appears safe.'
        };

        const types = {
            'phishing': 'danger',
            'suspicious': 'warning',
            'safe': 'success'
        };

        const message = messages[threatLevel] || 'Scan completed.';
        const toastType = types[threatLevel] || 'info';

        // Show toast notification
        this.showToast(`${scanType.toUpperCase()} Scan: ${message}`, toastType);

        // Show browser notification for threats
        if (threatLevel === 'phishing') {
            this.showBrowserNotification(
                'PhishGuard Alert',
                `Phishing detected in ${scanType} scan. Take immediate action.`,
                'danger'
            );
        }
    }

    setupWebSocket() {
        // This would connect to a WebSocket server for real-time updates
        // For now, we'll simulate with periodic checks
        this.setupPeriodicChecks();
    }

    setupPeriodicChecks() {
        // Check for new threats every 30 seconds (example)
        setInterval(() => {
            this.checkForNewThreats();
        }, 30000);
    }

    async checkForNewThreats() {
        try {
            const response = await fetch('/api/check-threats', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                if (data.new_threats && data.new_threats.length > 0) {
                    data.new_threats.forEach(threat => {
                        this.showToast(
                            `New threat detected: ${threat.description}`,
                            'warning',
                            8000
                        );
                    });
                }
            }
        } catch (error) {
            console.error('Error checking for threats:', error);
        }
    }
}

// Initialize notification manager
const notificationManager = new NotificationManager();

// Export for use in other scripts
window.NotificationManager = NotificationManager;
window.notificationManager = notificationManager;
