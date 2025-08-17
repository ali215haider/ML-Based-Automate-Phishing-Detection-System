class PhishShieldProContent {
    constructor() {
        this.init();
    }

    init() {
        this.createFloatingWidget();
        this.checkCurrentPage();
        this.setupMessageListener();
    }

    createFloatingWidget() {
        // Create floating widget for real-time protection
        const widget = document.createElement('div');
        widget.id = 'phishguard-widget';
        widget.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            cursor: pointer;
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
            border: 3px solid #fff;
        `;

        widget.innerHTML = `
            <svg width="24" height="24" fill="white" viewBox="0 0 24 24">
                <path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,7C13.4,7 14.8,8.6 14.8,10V11.5C15.4,11.5 16,12.1 16,12.7V16.5C16,17.1 15.4,17.7 14.8,17.7H9.2C8.6,17.7 8,17.1 8,16.5V12.7C8,12.1 8.6,11.5 9.2,11.5V10C9.2,8.6 10.6,7 12,7M12,8.2C11.2,8.2 10.5,8.7 10.5,10V11.5H13.5V10C13.5,8.7 12.8,8.2 12,8.2Z"/>
            </svg>
        `;

        widget.addEventListener('mouseenter', () => {
            widget.style.transform = 'scale(1.1)';
        });

        widget.addEventListener('mouseleave', () => {
            widget.style.transform = 'scale(1)';
        });

        widget.addEventListener('click', () => {
            this.scanCurrentPage();
        });

        document.body.appendChild(widget);
    }

    async checkCurrentPage() {
        const currentUrl = window.location.href;

        // Skip scanning for local files and extension pages
        if (currentUrl.startsWith('chrome://') || 
            currentUrl.startsWith('moz-extension://') || 
            currentUrl.startsWith('chrome-extension://') ||
            currentUrl.startsWith('file://')) {
            return;
        }

        try {
            const response = await fetch('http://localhost:5000/api/extension/scan-url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: currentUrl })
            });

            if (response.ok) {
                const result = await response.json();
                this.updateWidgetStatus(result);

                if (result.result === 'phishing') {
                    this.showWarning(result);
                }
            }
        } catch (error) {
            console.log('PhishGuard: Unable to connect to protection service');
        }
    }

    async scanCurrentPage() {
        const widget = document.getElementById('phishguard-widget');
        widget.style.animation = 'spin 1s linear infinite';

        await this.checkCurrentPage();

        widget.style.animation = '';
    }

    updateWidgetStatus(result) {
        const widget = document.getElementById('phishguard-widget');

        if (result.result === 'safe') {
            widget.style.background = 'linear-gradient(135deg, #4ade80 0%, #22c55e 100%)';
            widget.title = 'Safe - This site appears to be legitimate';
        } else if (result.result === 'phishing') {
            widget.style.background = 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)';
            widget.title = 'Dangerous - This site may be a phishing attempt';
        } else {
            widget.style.background = 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)';
            widget.title = 'Suspicious - Use caution with this site';
        }
    }

    showWarning(result) {
        // Create warning overlay
        const overlay = document.createElement('div');
        overlay.id = 'phishguard-warning';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
        `;

        const warning = document.createElement('div');
        warning.style.cssText = `
            background: white;
            padding: 40px;
            border-radius: 10px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        `;

        warning.innerHTML = `
            <div style="color: #dc2626; font-size: 48px; margin-bottom: 20px;">⚠️</div>
            <h2 style="color: #dc2626; margin-bottom: 20px;">Phishing Warning</h2>
            <p style="margin-bottom: 20px; line-height: 1.5;">
                This website may be a phishing attempt designed to steal your personal information.
                Confidence: ${(result.confidence * 100).toFixed(1)}%
            </p>
            <div style="margin-bottom: 30px;">
                <button id="phishguard-proceed" style="
                    background: #dc2626;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 5px;
                    margin-right: 10px;
                    cursor: pointer;
                ">Proceed Anyway</button>
                <button id="phishguard-goback" style="
                    background: #4ade80;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 5px;
                    cursor: pointer;
                ">Go Back</button>
            </div>
            <small style="color: #666;">Protected by PhishShield Pro</small>
        `;

        overlay.appendChild(warning);
        document.body.appendChild(overlay);

        // Event listeners
        document.getElementById('phishguard-proceed').addEventListener('click', () => {
            overlay.remove();
        });

        document.getElementById('phishguard-goback').addEventListener('click', () => {
            window.history.back();
        });
    }

    setupMessageListener() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.action === 'scanPage') {
                this.scanCurrentPage();
                sendResponse({ status: 'scanning' });
            }
        });
    }
}

// Add CSS animation for spinning
const style = document.createElement('style');
style.textContent = `
    @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
`;
document.head.appendChild(style);

// Initialize the content script
const phishShieldContent = new PhishShieldProContent();