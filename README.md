# 🛡️ Automate Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-CSRF%20Protected-red.svg)](#security)

A comprehensive web-based security platform that helps users identify and protect against phishing attacks through multiple detection methods, machine learning analysis, and educational resources.

## 🌟 Key Features

### 🔍 Multi-layered Detection
- **URL Analysis** - Real-time scanning of suspicious URLs
- **Email Analysis** - Detection of phishing emails and malicious content
- **HTML File Analysis** - Scanning of downloaded HTML files
- **Certificate Analysis** - SSL/TLS certificate verification
- **Machine Learning Classification** - AI-powered threat detection

### 👤 User Management
- **Secure Authentication** - Registration, login, and profile management
- **Password Reset** - Email-based password recovery system
- **Admin Dashboard** - Administrative controls and user management
- **Scan History** - Track and review previous scans

### 🎓 Educational Resources
- **Phishing Awareness** - Learn to identify phishing attempts
- **Security Best Practices** - Guidelines for online safety
- **Real-time Feedback** - Instant analysis results with explanations

### 🔧 Additional Tools
- **Browser Extension** - Chrome extension for real-time protection
- **API Endpoints** - Integration with external applications
- **Report Generation** - PDF reports of scan results
- **Threat Reporting** - Community-driven threat intelligence

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/Automate-Phishing-Detection-System.git
   cd Automate-Phishing-Detection-System
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirement.txt
   ```

4. **Set up environment variables**
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Edit .env with your configuration
   # See Configuration section below
   ```

5. **Initialize the database**
   ```bash
   python main.py
   ```

6. **Access the application**
   - Open your browser and navigate to `http://localhost:5000`
   - Default admin credentials: `admin` / `AdminPass123!`

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Application Settings
SECRET_KEY=your-secret-key-here
DEBUG=False
DATABASE_URL=sqlite:///phishing_detection.db

# Email Configuration (for password reset)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_DEFAULT_SENDER=noreply@phishguard.com

# Security Settings
WTF_CSRF_ENABLED=True
MAX_CONTENT_LENGTH=16777216
```

### Email Setup

For Gmail users:
1. Enable 2-Factor Authentication
2. Generate an App Password
3. Use the App Password in `MAIL_PASSWORD`

For detailed email setup instructions, see [EMAIL_SETUP_GUIDE.md](EMAIL_SETUP_GUIDE.md)

## 📖 Usage Guide

### For Regular Users

1. **Registration & Login**
   - Create an account at `/register`
   - Login with your credentials
   - Access your dashboard

2. **URL Scanning**
   - Navigate to "Scan URL"
   - Enter the suspicious URL
   - Review the analysis results

3. **Email Analysis**
   - Go to "Scan Email"
   - Paste email content or upload .eml files
   - Get detailed phishing analysis

4. **File Analysis**
   - Use "Scan HTML" for downloaded files
   - Upload HTML files for analysis
   - Receive comprehensive security reports

### For Administrators

1. **Admin Access**
   - Login with admin credentials
   - Access `/admin` dashboard

2. **User Management**
   - View all registered users
   - Monitor system statistics
   - Manage user accounts

3. **Dataset Management**
   - Populate ML training datasets
   - Update detection models
   - Review system performance

## 🔒 Security Features

- **CSRF Protection** - All forms protected against Cross-Site Request Forgery
- **Password Hashing** - Secure bcrypt password storage
- **Session Management** - Secure user session handling
- **Input Validation** - Comprehensive input sanitization
- **SQL Injection Prevention** - SQLAlchemy ORM protection
- **XSS Protection** - Content Security Policy headers

## 🧠 Machine Learning

The system uses advanced machine learning algorithms for phishing detection:

- **Feature Extraction** - URL, content, and metadata analysis
- **Classification Models** - Trained on extensive phishing datasets
- **Real-time Prediction** - Instant threat assessment
- **Continuous Learning** - Model updates with new threat data

## 🌐 Browser Extension

Install the Chrome extension for real-time protection:

1. Navigate to `extension/` folder
2. Load unpacked extension in Chrome
3. Enable real-time URL scanning
4. Get instant alerts for suspicious sites

## 📊 API Documentation

### Authentication Required Endpoints

```http
POST /api/scan-url
Content-Type: application/json

{
  "url": "https://example.com"
}
```

### Public Endpoints

```http
POST /api/extension/scan-url
Content-Type: application/json

{
  "url": "https://example.com"
}
```

For complete API documentation, see [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

## 🧪 Testing

### Run Tests

```bash
# Test email functionality
python test_email_auth.py

# Test detection algorithms
python test_enhanced_detection.py

# Test form submissions
python test_form_submission.py

# Test content analysis
python test_content_analysis.py
```

### Manual Testing

1. **Authentication Flow**
   - Test registration, login, logout
   - Verify password reset functionality

2. **Scanning Features**
   - Test URL, email, and file scanning
   - Verify result accuracy

3. **Admin Functions**
   - Test user management
   - Verify dataset operations

## 📁 Project Structure

```
Automate-Phishing-Detection-System/
├── 📄 Core Files
│   ├── app.py              # Flask application configuration
│   ├── main.py             # Application entry point
│   ├── routes.py           # URL routes and views
│   ├── models.py           # Database models
│   └── requirement.txt     # Python dependencies
│
├── 🎨 Frontend
│   ├── templates/          # HTML templates
│   └── static/            # CSS, JS, images
│
├── 🤖 Machine Learning
│   ├── models/            # Trained ML models
│   └── utils/             # Detection utilities
│
├── 🔧 Tools
│   ├── extension/         # Browser extension
│   ├── data/             # Datasets and configurations
│   └── uploads/          # File upload directory
│
└── 📚 Documentation
    ├── README.md          # This file
    ├── LICENSE           # MIT License
    └── *.md             # Additional documentation
```

## 🚀 Deployment

### Production Deployment

1. **Environment Setup**
   ```bash
   export FLASK_ENV=production
   export SECRET_KEY=your-production-secret
   ```

2. **Database Migration**
   ```bash
   # For PostgreSQL in production
   export DATABASE_URL=postgresql://user:pass@localhost/dbname
   ```

3. **Web Server**
   ```bash
   # Using Gunicorn
   gunicorn -w 4 -b 0.0.0.0:8000 main:app
   ```

### Docker Deployment

```dockerfile
# Dockerfile example
FROM python:3.9-slim
WORKDIR /app
COPY requirement.txt .
RUN pip install -r requirement.txt
COPY . .
EXPOSE 5000
CMD ["python", "main.py"]
```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Add tests** for new functionality
5. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to the branch**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### Development Guidelines

- Follow PEP 8 style guidelines
- Add docstrings to all functions
- Include unit tests for new features
- Update documentation as needed

## 🐛 Troubleshooting

### Common Issues

**Email not working?**
- Check Gmail App Password setup
- Verify SMTP settings in `.env`
- See [EMAIL_SETUP_GUIDE.md](EMAIL_SETUP_GUIDE.md)

**Login issues?**
- Verify admin credentials: `admin` / `AdminPass123!`
- Check database initialization
- Clear browser cache and cookies

**ML model errors?**
- Ensure all dependencies are installed
- Check model files in `models/` directory
- Verify scikit-learn version compatibility

**Performance issues?**
- Monitor system resources
- Check database query optimization
- Consider caching implementation

### Getting Help

- 📧 Email: support@phishguard.com
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/Automate-Phishing-Detection-System/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/Automate-Phishing-Detection-System/discussions)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Flask Community** - For the excellent web framework
- **scikit-learn** - For machine learning capabilities
- **Bootstrap** - For responsive UI components
- **Security Researchers** - For threat intelligence data
- **Open Source Community** - For continuous support and contributions

## 📈 Roadmap

### Version 2.0 (Planned)
- [ ] Advanced ML models with deep learning
- [ ] Real-time threat intelligence feeds
- [ ] Mobile application
- [ ] Advanced reporting and analytics
- [ ] Multi-language support
- [ ] Enterprise features

### Version 1.5 (In Progress)
- [x] Email functionality
- [x] Enhanced detection algorithms
- [x] Admin dashboard improvements
- [ ] API rate limiting
- [ ] Advanced logging

---

<div align="center">
  <strong>🛡️ Stay Safe Online with PhishGuard Pro 🛡️</strong>
  <br>
  <em>Protecting users from phishing attacks through advanced detection and education</em>
</div>

---

**⭐ If you find this project helpful, please consider giving it a star on GitHub!**