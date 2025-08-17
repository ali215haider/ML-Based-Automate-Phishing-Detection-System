#  Complete Project Documentation
# Automate Phishing Detection System

##  Project Overview

The **Automate Phishing Detection System** is a comprehensive web-based security platform that helps users identify and protect against phishing attacks through multiple detection methods, educational resources, and real-time analysis.

###  Key Features
- **Multi-layered Phishing Detection** (URL, Email, HTML, Certificate Analysis)
- **Machine Learning-based Classification**
- **Real-time Threat Analysis**
- **User Authentication & Profile Management**
- **Password Reset via Email**
- **Admin Dashboard**
- **Educational Resources**
- **Browser Extension Integration**
- **Scan History & Reporting**

---

## 🏗️ Project Architecture

### Technology Stack
- **Backend:** Flask (Python)
- **Database:** SQLite with SQLAlchemy ORM
- **Frontend:** HTML5, CSS3, JavaScript
- **Machine Learning:** scikit-learn, pandas, numpy
- **Email:** Flask-Mail with SMTP
- **Authentication:** Flask-Login with bcrypt
- **Security:** Flask-WTF (CSRF protection)

### Project Structure
```
Automate-Phishing-Detection-System/
├── 📁 Core Application Files
│   ├── app.py                 # Flask application configuration
│   ├── main.py               # Application entry point
│   ├── routes.py             # URL routes and view functions
│   ├── models.py             # Database models
│   └── requirements.txt      # Python dependencies
│
├── 📁 Templates & Static Files
│   ├── templates/            # HTML templates
│   │   ├── base.html        # Base template
│   │   ├── index.html       # Homepage
│   │   ├── login.html       # Login page
│   │   ├── register.html    # Registration page
│   │   ├── dashboard.html   # User dashboard
│   │   ├── forgot_password.html
│   │   ├── reset_password.html
│   │   ├── scan_*.html      # Scanning interfaces
│   │   └── admin.html       # Admin panel
│   └── static/              # CSS, JS, images
│       ├── css/style.css    # Main stylesheet
│       ├── js/main.js       # JavaScript functionality
│       └── favicon.ico      # Site icon
│
├── 📁 Machine Learning & Detection
│   ├── models/              # ML models and data
│   │   ├── phishing_model.pkl
│   │   ├── feature_scaler.pkl
│   │   └── feature_names.txt
│   └── utils/               # Detection utilities
│       ├── detection.py     # Main detection logic
│       ├── ml_model.py      # ML model handling
│       ├── feature_extraction.py
│       ├── certificate_analysis.py
│       ├── rules_engine.py  # Rule-based detection
│       └── train_model.py   # Model training
│
├── 📁 Data & Configuration
│   ├── data/                # Datasets and lists
│   │   ├── blacklist.txt    # Known malicious domains
│   │   ├── whitelist.txt    # Trusted domains
│   │   └── datasets/        # Training datasets
│   ├── instance/            # Database files
│   │   └── phishing_detection.db
│   ├── .env                 # Environment variables
│   └── .gitignore          # Git ignore rules
│
├── 📁 Browser Extension
│   ├── extension/
│   │   ├── manifest.json    # Extension configuration
│   │   ├── popup.html       # Extension popup
│   │   ├── popup.js         # Popup functionality
│   │   ├── background.js    # Background scripts
│   │   ├── content.js       # Content scripts
│   │   └── icons/           # Extension icons
│
└── 📁 Documentation & Testing
    ├── PROJECT_DOCUMENTATION.md
    ├── EMAIL_SETUP_GUIDE.md
    ├── GMAIL_APP_PASSWORD_SETUP.md
    ├── COMPLETE_PROJECT_DOCUMENTATION.md
    ├── test_*.py            # Test scripts
    └── README.md            # Project overview
```

---

## 🔧 Installation & Setup

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- Git

### Step 1: Clone Repository
```bash
git clone <repository-url>
cd Automate-Phishing-Detection-System
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Environment Configuration
1. **Create `.env` file:**
   ```env
   SECRET_KEY=your-secret-key-here
   DATABASE_URL=sqlite:///phishing_detection.db
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_app_password
   ```

2. **Gmail Setup (for password reset emails):**
   - Enable 2-Factor Authentication
   - Generate App Password
   - Update `MAIL_PASSWORD` in `.env`

### Step 4: Initialize Database
```bash
python main.py
```

### Step 5: Access Application
- **Web Interface:** http://127.0.0.1:5000
- **Default Admin:** username: `admin`, password: `admin123`

---

## 🎮 User Guide

### Authentication System
- **Registration:** Create new user accounts
- **Login/Logout:** Secure session management
- **Password Reset:** Email-based password recovery
- **Profile Management:** Update user information

### Detection Features

#### 1. URL Scanning
- **Purpose:** Analyze URLs for phishing indicators
- **Method:** ML model + rule-based detection
- **Features:** Domain reputation, URL structure analysis

#### 2. Email Analysis
- **Purpose:** Detect phishing emails
- **Method:** Content analysis, sender verification
- **Features:** Header analysis, attachment scanning

#### 3. HTML Content Scanning
- **Purpose:** Analyze web page content
- **Method:** DOM analysis, form detection
- **Features:** Suspicious form detection, script analysis

#### 4. Certificate Analysis
- **Purpose:** SSL/TLS certificate verification
- **Method:** Certificate chain validation
- **Features:** Issuer verification, expiration checking

### Dashboard Features
- **Scan History:** View previous scans
- **Statistics:** Detection metrics
- **Quick Actions:** Fast access to scanning tools
- **Profile Settings:** Account management

### Educational Resources
- **Phishing Awareness:** Learn about threats
- **Best Practices:** Security recommendations
- **Case Studies:** Real-world examples

---

## 🔒 Security Features

### Authentication & Authorization
- **Password Hashing:** bcrypt encryption
- **Session Management:** Flask-Login integration
- **CSRF Protection:** Flask-WTF tokens
- **Input Validation:** Form sanitization

### Email Security
- **Secure SMTP:** TLS encryption
- **Token-based Reset:** Time-limited tokens
- **One-time Use:** Tokens expire after use

### Data Protection
- **SQL Injection Prevention:** SQLAlchemy ORM
- **XSS Protection:** Template escaping
- **File Upload Security:** Type validation
- **Environment Variables:** Sensitive data protection

---

## 🤖 Machine Learning Components

### Model Architecture
- **Algorithm:** Random Forest Classifier
- **Features:** 30+ URL and content features
- **Training Data:** Curated phishing/legitimate datasets
- **Accuracy:** ~95% on test data

### Feature Extraction
```python
Features Include:
- URL length and structure
- Domain age and reputation
- SSL certificate status
- Redirect patterns
- Content analysis metrics
- Form and input detection
```

### Model Training
```bash
# Retrain model with new data
python utils/train_model.py
```

---

## 🌐 API Endpoints

### Public Endpoints
```
GET  /                    # Homepage
GET  /login              # Login page
POST /login              # Login processing
GET  /register           # Registration page
POST /register           # Registration processing
GET  /forgot-password    # Password reset request
POST /forgot-password    # Send reset email
GET  /reset-password/<token>  # Password reset form
POST /reset-password/<token> # Process password reset
```

### Protected Endpoints
```
GET  /dashboard          # User dashboard
GET  /profile            # User profile
POST /profile            # Update profile
GET  /scan-url           # URL scanning interface
POST /scan-url           # Process URL scan
GET  /scan-email         # Email scanning interface
POST /scan-email         # Process email scan
GET  /scan-html          # HTML scanning interface
POST /scan-html          # Process HTML scan
GET  /scan-certificate   # Certificate scanning interface
POST /scan-certificate   # Process certificate scan
GET  /scan-history       # View scan history
GET  /education          # Educational resources
```

### Admin Endpoints
```
GET  /admin              # Admin dashboard
POST /admin/populate-datasets  # Populate training data
```

### API Endpoints
```
POST /api/scan-url       # API URL scanning
POST /api/extension/scan-url  # Browser extension API
POST /api/password-strength   # Password strength check
POST /api/change-password     # Password change API
```

---

## 🔧 Configuration Options

### Environment Variables
```env
# Application Settings
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///phishing_detection.db
DEBUG=False

# Email Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_DEFAULT_SENDER=noreply@phishguard.com

# Security Settings
WTF_CSRF_ENABLED=True
WTF_CSRF_TIME_LIMIT=None
WTF_CSRF_SSL_STRICT=False

# File Upload Settings
MAX_CONTENT_LENGTH=16777216  # 16MB
UPLOAD_FOLDER=uploads
```

### Database Configuration
- **Development:** SQLite (default)
- **Production:** PostgreSQL recommended
- **Migrations:** Flask-Migrate support

---

## 🧪 Testing

### Test Scripts
```bash
# Test email functionality
python test_email_auth.py

# Test CSRF protection
python test_csrf.py

# Test form submissions
python test_form_submission.py

# Test enhanced detection
python test_enhanced_detection.py

# Test content analysis
python test_content_analysis.py
```

### Manual Testing
1. **Authentication Flow**
2. **Scanning Features**
3. **Email Functionality**
4. **Admin Features**
5. **Browser Extension**

---

## 🚀 Deployment

### Development Server
```bash
python main.py
# Access: http://127.0.0.1:5000
```

### Production Deployment

#### Using Gunicorn
```bash
gunicorn -w 4 -b 0.0.0.0:8000 main:app
```

#### Using Docker
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "main:app"]
```

#### Environment Setup
- Set production environment variables
- Configure reverse proxy (Nginx)
- Set up SSL certificates
- Configure database (PostgreSQL)

---

## 🔍 Troubleshooting

### Common Issues

#### Email Not Working
```
Problem: "Username and Password not accepted"
Solution: Use Gmail App Password instead of regular password
Steps: Enable 2FA → Generate App Password → Update .env
```

#### Database Errors
```
Problem: "no such table" errors
Solution: Initialize database
Command: python main.py (creates tables automatically)
```

#### Import Errors
```
Problem: Module not found
Solution: Install dependencies
Command: pip install -r requirements.txt
```

#### Permission Errors
```
Problem: File permission issues
Solution: Check file permissions and ownership
```

### Debug Mode
```python
# Enable debug mode in app.py
app.run(debug=True)
```

---

## 📈 Performance Optimization

### Database Optimization
- Index frequently queried columns
- Use connection pooling
- Implement query caching

### Caching Strategy
- Redis for session storage
- Cache ML model predictions
- Static file caching

### Security Hardening
- Rate limiting
- Input validation
- SQL injection prevention
- XSS protection

---

## 🔄 Maintenance

### Regular Tasks
- **Update Dependencies:** Monthly security updates
- **Database Backup:** Daily automated backups
- **Log Rotation:** Weekly log cleanup
- **Model Retraining:** Quarterly with new data

### Monitoring
- Application logs
- Error tracking
- Performance metrics
- Security alerts

---

## 🤝 Contributing

### Development Workflow
1. Fork repository
2. Create feature branch
3. Make changes
4. Add tests
5. Submit pull request

### Code Standards
- PEP 8 compliance
- Type hints
- Docstrings
- Unit tests

---

## 📄 License

This project is licensed under the MIT License. See LICENSE file for details.

---

## 📞 Support

For technical support or questions:
- Check troubleshooting section
- Review test scripts
- Consult setup guides
- Create GitHub issue

---

## 📚 Additional Resources

- **Email Setup Guide:** `EMAIL_SETUP_GUIDE.md`
- **Gmail App Password Setup:** `GMAIL_APP_PASSWORD_SETUP.md`
- **Project Documentation:** `PROJECT_DOCUMENTATION.md`
- **Browser Extension Guide:** `extension/README.md`

---

*Last Updated: August 2025*
*Version: 2.0*