# PhishShield Pro Browser Extension

A real-time phishing detection browser extension that works with the PhishShield Pro detection system.

## Features

- **Real-time URL Scanning**: Automatically scans websites as you browse
- **Floating Protection Widget**: Visual indicator of website safety status
- **Instant Alerts**: Immediate warnings for phishing and suspicious sites
- **Manual Scanning**: Click-to-scan functionality for on-demand checks
- **Dashboard Integration**: Quick access to the main PhishShield Pro dashboard
- **Customizable Settings**: Configure protection levels and notifications

## Installation Guide

### Prerequisites

1. **PhishShield Pro Server**: Ensure the main application is running on `http://localhost:5000`
2. **Chrome Browser**: This extension is designed for Chrome/Chromium-based browsers

### Step-by-Step Installation

#### Method 1: Developer Mode (Recommended for Testing)

1. **Open Chrome Extensions Page**:
   - Type `chrome://extensions/` in your address bar
   - Or go to Chrome Menu → More Tools → Extensions

2. **Enable Developer Mode**:
   - Toggle the "Developer mode" switch in the top-right corner

3. **Load the Extension**:
   - Click "Load unpacked" button
   - Navigate to your project folder: `Automate-Phishing-Detection-System/extension/`
   - Select the extension folder and click "Select Folder"

4. **Verify Installation**:
   - You should see "PhishShield Pro - Phishing Detection" in your extensions list
   - The extension icon should appear in your browser toolbar

#### Method 2: Package Installation (For Distribution)

1. **Package the Extension**:
   - Go to `chrome://extensions/`
   - Click "Pack extension"
   - Select the extension folder
   - This creates a `.crx` file

2. **Install the Package**:
   - Drag and drop the `.crx` file into Chrome
   - Click "Add Extension" when prompted

## How to Use the Extension

### Real-Time Protection

1. **Automatic Scanning**:
   - The extension automatically scans websites as you navigate
   - A floating widget appears on each page showing protection status

2. **Protection Widget**:
   - **Green**: Safe website
   - **Yellow**: Suspicious content detected
   - **Red**: Phishing/malicious site detected
   - **Blue**: Scanning in progress

### Manual Scanning

1. **Click the Widget**: Click the floating shield icon to manually scan the current page
2. **Extension Popup**: Click the extension icon in the toolbar to:
   - View current page status
   - Access scan history
   - Configure settings
   - Open the main dashboard

### Extension Popup Features

#### Status Display
- **Current Page Status**: Shows if the current page is safe, suspicious, or dangerous
- **Confidence Level**: Displays the detection confidence percentage
- **Scan Details**: Shows detection method and timing

#### Quick Actions
- **Scan Now**: Manually trigger a scan of the current page
- **Report Phishing**: Report a suspected phishing site
- **Open Dashboard**: Access the full PhishShield Pro web interface

#### Settings
- **Real-time Protection**: Enable/disable automatic scanning
- **Auto-scan Links**: Scan links before clicking
- **Block Downloads**: Block downloads from suspicious sites
- **Show Notifications**: Enable/disable browser notifications

## Understanding Scan Results

### Result Types

1. **Safe** (Green):
   - Website appears legitimate
   - No phishing indicators detected
   - Safe to proceed

2. **Suspicious** (Yellow):
   - Some concerning characteristics detected
   - Exercise caution
   - Verify website authenticity

3. **Phishing** (Red):
   - High probability of phishing attempt
   - **DO NOT** enter personal information
   - Leave the website immediately

### Detection Methods

- **Machine Learning**: AI-powered analysis of website characteristics
- **Blacklist**: Known malicious domains database
- **Rule-based**: Heuristic analysis of suspicious patterns

## Troubleshooting

### Common Issues

#### Extension Not Working
1. **Check Server Status**: Ensure PhishShield Pro server is running on `http://localhost:5000`
2. **Refresh Extension**: Disable and re-enable the extension
3. **Clear Cache**: Clear browser cache and reload pages

#### No Floating Widget
1. **Check Permissions**: Ensure extension has access to all websites
2. **Reload Page**: Refresh the current page
3. **Check Console**: Open Developer Tools → Console for error messages

#### API Connection Errors
1. **Server Running**: Verify the Flask application is active
2. **Port Conflicts**: Ensure port 5000 is not blocked
3. **CORS Issues**: Check browser console for cross-origin errors

### Debug Mode

1. **Open Developer Tools**: Right-click extension icon → Inspect popup
2. **Check Console**: Look for error messages or API failures
3. **Network Tab**: Monitor API requests to the server

## Security Considerations

### Data Privacy
- URLs are sent to the local server for analysis
- No data is stored permanently without user account
- Extension operates locally with your PhishShield Pro installation

### Permissions Explained
- **activeTab**: Access current tab for scanning
- **storage**: Save extension settings
- **notifications**: Show security alerts
- **tabs**: Monitor navigation for real-time protection
- **webNavigation**: Detect page changes
- **alarms**: Schedule periodic tasks

## Advanced Configuration

### Custom Server URL

To use with a different server (production deployment):

1. Edit `background.js`:
   ```javascript
   this.serverUrl = 'https://your-domain.com'; // Change this line
   ```

2. Edit `content.js` and `popup.js`:
   ```javascript
   // Update fetch URLs to your server
   const response = await fetch('https://your-domain.com/api/extension/scan-url', {
   ```

3. Update `manifest.json` host permissions:
   ```json
   "host_permissions": [
       "https://your-domain.com/*"
   ]
   ```

### Performance Tuning

- **Scan Cache**: Results are cached for 5 minutes to improve performance
- **Rate Limiting**: Automatic throttling prevents server overload
- **Background Processing**: Scans run asynchronously without blocking browsing

## Support

For issues or questions:
1. Check the main PhishShield Pro documentation
2. Verify server logs for API errors
3. Use browser Developer Tools for debugging
4. Ensure all permissions are granted to the extension

## Version Information

- **Extension Version**: 1.0.0
- **Manifest Version**: 3 (Chrome Extensions Manifest V3)
- **Compatible Browsers**: Chrome 88+, Edge 88+, Opera 74+

---

**Note**: This extension requires the PhishShield Pro server to be running for full functionality. Make sure your Flask application is active before using the extension.