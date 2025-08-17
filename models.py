
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import secrets
import hashlib

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expires = db.Column(db.DateTime)
    
    # Relationships
    scan_history = db.relationship('ScanHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        if not self.is_strong_password(password):
            raise ValueError("Password does not meet strength requirements")
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def is_strong_password(password):
        """Check if password meets strength requirements"""
        if len(password) < 8:
            return False
        
        # Check for uppercase, lowercase, digits, and special characters
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        return has_upper and has_lower and has_digit and has_special
    
    def can_access_user_data(self, target_user_id):
        """Check if user can access another user's data"""
        return self.is_admin or self.id == target_user_id
    
    def generate_reset_token(self):
        """Generate a password reset token"""
        token = secrets.token_urlsafe(32)
        self.reset_token = hashlib.sha256(token.encode()).hexdigest()
        self.reset_token_expires = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
        return token
    
    def verify_reset_token(self, token):
        """Verify a password reset token"""
        if not self.reset_token or not self.reset_token_expires:
            return False
        
        if datetime.utcnow() > self.reset_token_expires:
            return False
        
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token_hash == self.reset_token
    
    def clear_reset_token(self):
        """Clear the password reset token"""
        self.reset_token = None
        self.reset_token_expires = None
    
    def __repr__(self):
        return f'<User {self.username}>'

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # url, email, html, certificate
    content = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(20), nullable=False)  # safe, phishing, suspicious
    confidence = db.Column(db.Float, default=0.0)
    detection_methods = db.Column(db.Text)  # JSON string of detection methods used
    features_detected = db.Column(db.Text)  # JSON string of features detected
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    
    def __repr__(self):
        return f'<ScanHistory {self.scan_type}: {self.result}>'

class PhishingReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, reviewed, resolved
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Define explicit relationships to avoid ambiguity
    reporter = db.relationship('User', foreign_keys=[user_id], backref='submitted_reports')
    reviewer = db.relationship('User', foreign_keys=[reviewed_by], backref='reviewed_reports')
    
    def __repr__(self):
        return f'<PhishingReport {self.report_type}: {self.status}>'

class BlacklistDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    source = db.Column(db.String(100))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<BlacklistDomain {self.domain}>'

class WhitelistDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<WhitelistDomain {self.domain}>'

class CertificateAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    certificate_data = db.Column(db.Text)  # JSON string of certificate details
    is_valid = db.Column(db.Boolean)
    is_expired = db.Column(db.Boolean)
    is_self_signed = db.Column(db.Boolean)
    issuer = db.Column(db.String(255))
    subject = db.Column(db.String(255))
    valid_from = db.Column(db.DateTime)
    valid_to = db.Column(db.DateTime)
    signature_algorithm = db.Column(db.String(100))
    key_size = db.Column(db.Integer)
    analysis_result = db.Column(db.String(20))  # trusted, suspicious, invalid
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<CertificateAnalysis {self.domain}: {self.analysis_result}>'

class MLDataset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dataset_type = db.Column(db.String(50), nullable=False)  # url, email, html
    content = db.Column(db.Text, nullable=False)
    label = db.Column(db.String(20), nullable=False)  # legitimate, phishing
    features = db.Column(db.Text)  # JSON string of extracted features
    source = db.Column(db.String(100))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<MLDataset {self.dataset_type}: {self.label}>'
