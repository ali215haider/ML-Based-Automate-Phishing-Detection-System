
class PhishGuardPopup {
    constructor() {
        this.init();
    }

    async init() {
        await this.loadSettings();
        await this.updateStats();
        await this.checkCurrentPage();
        this.bindEvents();
        this.startPeriodicUpdates();
    }

    async loadSettings() {
        const settings = await chrome.storage.sync.get({
            realtimeProtection: true,
            autoScanLinks: true,
            blockDownloads: false,
            showNotifications: true
        });

        document.getElementById('realtimeProtection').checked = settings.realtimeProtection;
        document.getElementById('autoScanLinks').checked = settings.autoScanLinks;
        document.getElementById('blockDownloads').checked = settings.blockDownloads;
        document.getElementById('showNotifications').checked = settings.showNotifications;
    }

    async saveSettings() {
        const settings = {
            realtimeProtection: document.getElementById('realtimeProtection').checked,
            autoScanLinks: document.getElementById('autoScanLinks').checked,
            blockDownloads: document.getElementById('blockDownloads').checked,
            showNotifications: document.getElementById('showNotifications').checked
        };

        await chrome.storage.sync.set(settings);
        
        // Notify background script of settings change
        chrome.runtime.sendMessage({
            action: 'settingsUpdated',
            settings: settings
        });
    }

    bindEvents() {
        // Scan button
        document.getElementById('scanNow').addEventListener('click', () => {
            this.scanCurrentPage();
        });

        // Report phishing button
        document.getElementById('reportPhishing').addEventListener('click', () => {
            this.reportPhishing();
        });

        // Open dashboard button
        document.getElementById('openDashboard').addEventListener('click', () => {
            chrome.tabs.create({ url: 'http://localhost:5000/dashboard' });
        });

        // Settings toggles
        const toggles = ['realtimeProtection', 'autoScanLinks', 'blockDownloads', 'showNotifications'];
        toggles.forEach(toggleId => {
            document.getElementById(toggleId).addEventListener('change', () => {
                this.saveSettings();
            });
        });
    }

    async checkCurrentPage() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            if (tab && tab.url) {
                this.updateStatus('scanning', 'Scanning current page...', 'Analyzing for threats');
                
                const result = await this.scanUrl(tab.url);
                this.displayScanResult(result);
            }
        } catch (error) {
            console.error('Error checking current page:', error);
            this.updateStatus('error', 'Error scanning page', 'Please try again');
        }
    }

    async scanCurrentPage() {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab && tab.url) {
            this.updateStatus('scanning', 'Scanning...', 'Please wait');
            
            const result = await this.scanUrl(tab.url);
            this.displayScanResult(result);
            
            // Update stats
            await this.incrementScanCount();
            await this.updateStats();
        }
    }

    async scanUrl(url) {
        try {
            const response = await fetch('http://localhost:5000/api/extension/scan-url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            if (response.ok) {
                return await response.json();
            } else {
                throw new Error('Scan request failed');
            }
        } catch (error) {
            console.error('Scan error:', error);
            return {
                result: 'error',
                confidence: 0,
                details: { error: 'Unable to connect to PhishGuard server' }
            };
        }
    }

    displayScanResult(result) {
        const statusMap = {
            'safe': {
                icon: '✅',
                class: 'status-safe',
                text: 'Page is Safe',
                details: 'No threats detected'
            },
            'suspicious': {
                icon: '⚠️',
                class: 'status-warning',
                text: 'Suspicious Content',
                details: 'Exercise caution'
            },
            'phishing': {
                icon: '🚫',
                class: 'status-danger',
                text: 'Phishing Detected!',
                details: 'Do not enter personal information'
            },
            'error': {
                icon: '❌',
                class: 'status-danger',
                text: 'Scan Error',
                details: 'Unable to analyze page'
            }
        };

        const status = statusMap[result.result] || statusMap['error'];
        
        this.updateStatus(
            result.result,
            status.text,
            `${status.details} (${Math.round(result.confidence * 100)}% confidence)`
        );

        // Update threat counter if phishing detected
        if (result.result === 'phishing') {
            this.incrementThreatCount();
        }

        // Show notification if enabled
        this.showNotificationIfEnabled(result);
    }

    updateStatus(type, text, details) {
        const statusIcon = document.getElementById('statusIcon');
        const statusText = document.getElementById('statusText');
        const statusDetails = document.getElementById('statusDetails');

        const iconMap = {
            'safe': '✅',
            'suspicious': '⚠️',
            'phishing': '🚫',
            'scanning': '🔍',
            'error': '❌'
        };

        const classMap = {
            'safe': 'status-safe',
            'suspicious': 'status-warning',
            'phishing': 'status-danger',
            'scanning': 'status-scanning',
            'error': 'status-danger'
        };

        statusIcon.innerHTML = `<span>${iconMap[type] || '❓'}</span>`;
        statusIcon.className = `status-icon ${classMap[type] || 'status-scanning'}`;
        statusText.textContent = text;
        statusDetails.textContent = details;
    }

    async showNotificationIfEnabled(result) {
        const settings = await chrome.storage.sync.get({ showNotifications: true });
        
        if (settings.showNotifications && result.result === 'phishing') {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: 'PhishGuard Alert',
                message: 'Phishing site detected! Do not enter personal information.'
            });
        }
    }

    async reportPhishing() {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab && tab.url) {
            // Open dashboard with pre-filled report
            const reportUrl = `http://localhost:5000/profile?report_url=${encodeURIComponent(tab.url)}`;
            chrome.tabs.create({ url: reportUrl });
        }
    }

    async updateStats() {
        const stats = await chrome.storage.local.get({
            todayScans: 0,
            threatsBlocked: 0,
            lastResetDate: new Date().toDateString()
        });

        // Reset daily stats if new day
        const today = new Date().toDateString();
        if (stats.lastResetDate !== today) {
            stats.todayScans = 0;
            stats.lastResetDate = today;
            await chrome.storage.local.set(stats);
        }

        document.getElementById('todayScans').textContent = stats.todayScans;
        document.getElementById('threatsBlocked').textContent = stats.threatsBlocked;
    }

    async incrementScanCount() {
        const stats = await chrome.storage.local.get({ todayScans: 0 });
        stats.todayScans++;
        await chrome.storage.local.set(stats);
    }

    async incrementThreatCount() {
        const stats = await chrome.storage.local.get({ threatsBlocked: 0 });
        stats.threatsBlocked++;
        await chrome.storage.local.set(stats);
        await this.updateStats();
    }

    startPeriodicUpdates() {
        // Update stats every 30 seconds
        setInterval(() => {
            this.updateStats();
        }, 30000);
    }
}

class PhishShieldProPopup {
    constructor() {
        this.init();
    }

    async init() {
        await this.loadSettings();
        await this.updateStats();
        await this.checkCurrentPage();
        this.bindEvents();
        this.startPeriodicUpdates();
    }

    async loadSettings() {
        const settings = await chrome.storage.sync.get({
            realtimeProtection: true,
            autoScanLinks: true,
            blockDownloads: false,
            showNotifications: true
        });

        document.getElementById('realtimeProtection').checked = settings.realtimeProtection;
        document.getElementById('autoScanLinks').checked = settings.autoScanLinks;
        document.getElementById('blockDownloads').checked = settings.blockDownloads;
        document.getElementById('showNotifications').checked = settings.showNotifications;
    }

    async saveSettings() {
        const settings = {
            realtimeProtection: document.getElementById('realtimeProtection').checked,
            autoScanLinks: document.getElementById('autoScanLinks').checked,
            blockDownloads: document.getElementById('blockDownloads').checked,
            showNotifications: document.getElementById('showNotifications').checked
        };

        await chrome.storage.sync.set(settings);
        
        // Notify background script of settings change
        chrome.runtime.sendMessage({
            action: 'settingsUpdated',
            settings: settings
        });
    }

    bindEvents() {
        // Scan button
        document.getElementById('scanNow').addEventListener('click', () => {
            this.scanCurrentPage();
        });

        // Report phishing button
        document.getElementById('reportPhishing').addEventListener('click', () => {
            this.reportPhishing();
        });

        // Open dashboard button
        document.getElementById('openDashboard').addEventListener('click', () => {
            chrome.tabs.create({ url: 'http://localhost:5000/dashboard' });
        });

        // Settings toggles
        const toggles = ['realtimeProtection', 'autoScanLinks', 'blockDownloads', 'showNotifications'];
        toggles.forEach(toggleId => {
            document.getElementById(toggleId).addEventListener('change', () => {
                this.saveSettings();
            });
        });
    }

    async checkCurrentPage() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            if (tab && tab.url) {
                this.updateStatus('scanning', 'Scanning current page...', 'Analyzing for threats');
                
                const result = await this.scanUrl(tab.url);
                this.displayScanResult(result);
            }
        } catch (error) {
            console.error('Error checking current page:', error);
            this.updateStatus('error', 'Error scanning page', 'Please try again');
        }
    }

    async scanCurrentPage() {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab && tab.url) {
            this.updateStatus('scanning', 'Scanning...', 'Please wait');
            
            const result = await this.scanUrl(tab.url);
            this.displayScanResult(result);
            
            // Update stats
            await this.incrementScanCount();
            await this.updateStats();
        }
    }

    async scanUrl(url) {
        try {
            const response = await fetch('http://localhost:5000/api/extension/scan-url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            if (response.ok) {
                return await response.json();
            } else {
                throw new Error('Scan request failed');
            }
        } catch (error) {
            console.error('Scan error:', error);
            return {
                result: 'error',
                confidence: 0,
                details: { error: 'Unable to connect to PhishGuard server' }
            };
        }
    }

    displayScanResult(result) {
        const statusMap = {
            'safe': {
                icon: '✅',
                class: 'status-safe',
                text: 'Page is Safe',
                details: 'No threats detected'
            },
            'suspicious': {
                icon: '⚠️',
                class: 'status-warning',
                text: 'Suspicious Content',
                details: 'Exercise caution'
            },
            'phishing': {
                icon: '🚫',
                class: 'status-danger',
                text: 'Phishing Detected!',
                details: 'Do not enter personal information'
            },
            'error': {
                icon: '❌',
                class: 'status-danger',
                text: 'Scan Error',
                details: 'Unable to analyze page'
            }
        };

        const status = statusMap[result.result] || statusMap['error'];
        
        this.updateStatus(
            result.result,
            status.text,
            `${status.details} (${Math.round(result.confidence * 100)}% confidence)`
        );

        // Update threat counter if phishing detected
        if (result.result === 'phishing') {
            this.incrementThreatCount();
        }

        // Show notification if enabled
        this.showNotificationIfEnabled(result);
    }

    updateStatus(type, text, details) {
        const statusIcon = document.getElementById('statusIcon');
        const statusText = document.getElementById('statusText');
        const statusDetails = document.getElementById('statusDetails');

        const iconMap = {
            'safe': '✅',
            'suspicious': '⚠️',
            'phishing': '🚫',
            'scanning': '🔍',
            'error': '❌'
        };

        const classMap = {
            'safe': 'status-safe',
            'suspicious': 'status-warning',
            'phishing': 'status-danger',
            'scanning': 'status-scanning',
            'error': 'status-danger'
        };

        statusIcon.innerHTML = `<span>${iconMap[type] || '❓'}</span>`;
        statusIcon.className = `status-icon ${classMap[type] || 'status-scanning'}`;
        statusText.textContent = text;
        statusDetails.textContent = details;
    }

    async showNotificationIfEnabled(result) {
        const settings = await chrome.storage.sync.get({ showNotifications: true });
        
        if (settings.showNotifications && result.result === 'phishing') {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: 'PhishGuard Alert',
                message: 'Phishing site detected! Do not enter personal information.'
            });
        }
    }

    async reportPhishing() {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab && tab.url) {
            // Open dashboard with pre-filled report
            const reportUrl = `http://localhost:5000/profile?report_url=${encodeURIComponent(tab.url)}`;
            chrome.tabs.create({ url: reportUrl });
        }
    }

    async updateStats() {
        const stats = await chrome.storage.local.get({
            todayScans: 0,
            threatsBlocked: 0,
            lastResetDate: new Date().toDateString()
        });

        // Reset daily stats if new day
        const today = new Date().toDateString();
        if (stats.lastResetDate !== today) {
            stats.todayScans = 0;
            stats.lastResetDate = today;
            await chrome.storage.local.set(stats);
        }

        document.getElementById('todayScans').textContent = stats.todayScans;
        document.getElementById('threatsBlocked').textContent = stats.threatsBlocked;
    }

    async incrementScanCount() {
        const stats = await chrome.storage.local.get({ todayScans: 0 });
        stats.todayScans++;
        await chrome.storage.local.set(stats);
    }

    async incrementThreatCount() {
        const stats = await chrome.storage.local.get({ threatsBlocked: 0 });
        stats.threatsBlocked++;
        await chrome.storage.local.set(stats);
        await this.updateStats();
    }

    startPeriodicUpdates() {
        // Update stats every 30 seconds
        setInterval(() => {
            this.updateStats();
        }, 30000);
    }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PhishShieldProPopup();
});

