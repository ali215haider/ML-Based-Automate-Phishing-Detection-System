import json
import os
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from werkzeug.utils import secure_filename
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import io
from collections import Counter
# Import app after other imports to avoid circular import
from models import db
from models import User, ScanHistory, PhishingReport, CertificateAnalysis, MLDataset
from utils.detection import analyze_url, analyze_email, analyze_html_file

# Import app at the end to avoid circular import
from app import app, mail
from utils.certificate_analysis import analyze_certificate
import re


@app.route('/')
def index():
    return render_template('index.html')


# Certificate scanning route moved to avoid duplication


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        # Strong password validation
        if not User.is_strong_password(password):
            flash(
                'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters',
                'error')
            return render_template('register.html')

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')

        # Create new user
        try:
            user = User()
            user.username = username
            user.email = email
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        print("\n=== DEBUG LOGIN ATTEMPT ===")
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        csrf_token = request.form.get('csrf_token', '')
        
        print(f"Form data received:")
        print(f"  Username: '{username}' (length: {len(username)})")
        print(f"  Password: '{password}' (length: {len(password)})")
        print(f"  CSRF Token: '{csrf_token[:20] if csrf_token else 'None'}...'")
        print(f"  Form keys: {list(request.form.keys())}")

        user = User.query.filter_by(username=username).first()
        print(f"User found: {user is not None}")
        
        if user:
            print(f"User details: ID={user.id}, Username='{user.username}', Admin={user.is_admin}")
            password_valid = user.check_password(password)
            print(f"Password check result: {password_valid}")
            
            if password_valid:
                print("LOGIN SUCCESS - Redirecting to dashboard")
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(
                    url_for('dashboard'))
            else:
                print("LOGIN FAILED - Invalid password")
        else:
            print("LOGIN FAILED - User not found")
            
        flash('Invalid username or password', 'error')
        print("=== END DEBUG LOGIN ATTEMPT ===\n")

    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            try:
                # Generate reset token
                token = user.generate_reset_token()
                db.session.commit()
                
                # Send reset email
                reset_url = url_for('reset_password', token=token, _external=True)
                
                msg = Message(
                    'Password Reset Request - PhishGuard',
                    recipients=[user.email]
                )
                
                msg.html = f'''
                <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                            <h1 style="color: white; margin: 0; font-size: 28px;">🛡️ PhishGuard</h1>
                            <p style="color: #f0f0f0; margin: 10px 0 0 0;">Password Reset Request</p>
                        </div>
                        
                        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
                            <h2 style="color: #333; margin-top: 0;">Hello {user.username},</h2>
                            
                            <p>We received a request to reset your password for your PhishGuard account.</p>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{reset_url}" 
                                   style="background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Your Password</a>
                            </div>
                            
                            <p><strong>Important:</strong></p>
                            <ul>
                                <li>This link will expire in 1 hour for security reasons</li>
                                <li>If you didn't request this reset, please ignore this email</li>
                                <li>Your password will remain unchanged until you create a new one</li>
                            </ul>
                            
                            <p>If the button doesn't work, copy and paste this link into your browser:</p>
                            <p style="word-break: break-all; background: #e9e9e9; padding: 10px; border-radius: 5px; font-family: monospace;">{reset_url}</p>
                            
                            <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                            
                            <p style="font-size: 14px; color: #666;">
                                Best regards,<br>
                                The PhishGuard Security Team<br>
                                <em>Protecting you from phishing attacks</em>
                            </p>
                        </div>
                    </div>
                </body>
                </html>
                '''
                
                mail.send(msg)
                flash('If an account with that email exists, password reset instructions have been sent.', 'info')
                
            except Exception as e:
                # Log the error but don't reveal it to the user
                print(f"Email sending error: {str(e)}")
                flash('If an account with that email exists, password reset instructions have been sent.', 'info')
        else:
            # Don't reveal if email exists or not for security
            flash('If an account with that email exists, password reset instructions have been sent.', 'info')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Find user by token
    users = User.query.all()
    user = None
    for u in users:
        if u.verify_reset_token(token):
            user = u
            break
    
    if not user:
        flash('Invalid or expired reset token. Please request a new password reset.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not password or not confirm_password:
            flash('Please fill in all fields', 'error')
            return render_template('reset_password.html', token=token)
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        
        try:
            user.set_password(password)
            user.clear_reset_token()
            db.session.commit()
            
            flash('Your password has been successfully reset. You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
            
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('reset_password.html', token=token)
        except Exception as e:
            flash('An error occurred while resetting your password. Please try again.', 'error')
            return render_template('reset_password.html', token=token)
    
    return render_template('reset_password.html', token=token)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    # Admin can see all users' data, secondary users only their own
    if current_user.is_admin:
        recent_scans = ScanHistory.query.order_by(
            ScanHistory.scan_time.desc()).limit(10).all()
        total_scans = ScanHistory.query.count()
        phishing_detected = ScanHistory.query.filter_by(
            result='phishing').count()
        safe_scans = ScanHistory.query.filter_by(result='safe').count()
    else:
        recent_scans = ScanHistory.query.filter_by(
            user_id=current_user.id).order_by(
                ScanHistory.scan_time.desc()).limit(5).all()
        total_scans = ScanHistory.query.filter_by(
            user_id=current_user.id).count()
        phishing_detected = ScanHistory.query.filter_by(
            user_id=current_user.id, result='phishing').count()
        safe_scans = ScanHistory.query.filter_by(user_id=current_user.id,
                                                 result='safe').count()

    stats = {
        'total_scans': total_scans,
        'phishing_detected': phishing_detected,
        'safe_scans': safe_scans,
        'suspicious_scans': total_scans - phishing_detected - safe_scans
    }

    return render_template('dashboard.html',
                           recent_scans=recent_scans,
                           stats=stats)


@app.route('/scan-url', methods=['GET', 'POST'])
@login_required
def scan_url():
    if request.method == 'POST':
        url = request.form['url'].strip()

        if not url:
            flash('Please enter a URL to scan', 'error')
            return render_template('scan_url.html')

        # Analyze the URL
        result = analyze_url(url)

        # Save scan history
        scan = ScanHistory()
        scan.user_id = current_user.id
        scan.scan_type = 'url'
        scan.content = url
        scan.result = result['result']
        scan.confidence = result['confidence']
        scan.detection_methods = json.dumps(result['detection_methods'])
        scan.features_detected = json.dumps(result['features'])
        scan.ip_address = request.remote_addr
        scan.user_agent = request.headers.get('User-Agent')
        db.session.add(scan)
        db.session.commit()

        return render_template('scan_url.html', result=result, url=url)

    return render_template('scan_url.html')


@app.route('/scan-email', methods=['GET', 'POST'])
@login_required
def scan_email():
    if request.method == 'POST':
        email_content = ''
        source_type = 'text'

        # Check if file was uploaded
        if 'email_file' in request.files and request.files[
                'email_file'].filename:
            file = request.files['email_file']
            if file and file.filename:
                filename = secure_filename(file.filename)

                # Check file extension - only allow .eml files
                if not filename.lower().endswith('.eml'):
                    flash('Please upload only .eml files for email analysis',
                          'error')
                    return render_template('scan_email.html')

                try:
                    email_content = file.read().decode('utf-8',
                                                       errors='ignore')
                    source_type = 'file'
                except Exception as e:
                    flash(f'Error reading file: {str(e)}', 'error')
                    return render_template('scan_email.html')
        else:
            # Get text content
            email_content = request.form.get('email_content', '').strip()

        if not email_content:
            flash('Please enter email content or upload an .eml file to scan',
                  'error')
            return render_template('scan_email.html')

        # Analyze the email
        result = analyze_email(email_content)

        # Save scan history
        scan = ScanHistory()
        scan.user_id = current_user.id
        scan.scan_type = 'email'
        scan.content = f"Source: {source_type} - {email_content[:1000]}"
        scan.result = result['result']
        scan.confidence = result['confidence']
        scan.detection_methods = json.dumps(result['detection_methods'])
        scan.features_detected = json.dumps(result['features'])
        scan.ip_address = request.remote_addr
        scan.user_agent = request.headers.get('User-Agent')
        db.session.add(scan)
        db.session.commit()

        return render_template('scan_email.html',
                               result=result,
                               source_type=source_type)

    return render_template('scan_email.html')


@app.route('/scan-html', methods=['GET', 'POST'])
@login_required
def scan_html():
    if request.method == 'POST':
        if 'html_file' not in request.files:
            flash('No file selected', 'error')
            return render_template('scan_html.html')

        file = request.files['html_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return render_template('scan_html.html')

        filename = secure_filename(file.filename)

        # Check file extension - only allow .html files
        if not filename.lower().endswith(('.html', '.htm')):
            flash('Please upload only .html or .htm files', 'error')
            return render_template('scan_html.html')

        # Read file content
        html_content = file.read().decode('utf-8', errors='ignore')

        # Analyze the HTML
        result = analyze_html_file(html_content, filename)

        # Save scan history
        scan = ScanHistory()
        scan.user_id = current_user.id
        scan.scan_type = 'html'
        scan.content = f"File: {filename}"
        scan.result = result['result']
        scan.confidence = result['confidence']
        scan.detection_methods = json.dumps(result['detection_methods'])
        scan.features_detected = json.dumps(result['features'])
        scan.ip_address = request.remote_addr
        scan.user_agent = request.headers.get('User-Agent')
        db.session.add(scan)
        db.session.commit()

        return render_template('scan_html.html',
                               result=result,
                               filename=filename)

    return render_template('scan_html.html')


@app.route('/scan-certificate', methods=['GET', 'POST'])
@login_required
def scan_certificate():
    if request.method == 'POST':
        domain = request.form['domain'].strip()

        if not domain:
            flash('Please enter a domain to scan', 'error')
            return render_template('scan_certificate.html')

        # Analyze the certificate
        result = analyze_certificate(domain)
        
        # Save certificate analysis
        cert_analysis = CertificateAnalysis()
        cert_analysis.user_id = current_user.id
        cert_analysis.domain = domain
        cert_analysis.certificate_data = json.dumps(
            result.get('certificate_data', {}))
        cert_analysis.is_valid = result.get('is_valid', False)
        cert_analysis.is_expired = result.get('is_expired', True)
        cert_analysis.is_self_signed = result.get('is_self_signed', False)
        cert_analysis.issuer = result.get('issuer', '')
        cert_analysis.subject = result.get('subject', '')
        cert_analysis.valid_from = result.get('valid_from')
        cert_analysis.valid_to = result.get('valid_to')
        cert_analysis.signature_algorithm = result.get('signature_algorithm',
                                                       '')
        cert_analysis.key_size = result.get('key_size', 0)
        cert_analysis.analysis_result = result.get('result', 'invalid')
        db.session.add(cert_analysis)

        # Save scan history
        scan = ScanHistory()
        scan.user_id = current_user.id
        scan.scan_type = 'certificate'
        scan.content = domain
        scan.result = result['result']
        scan.confidence = result['confidence']
        scan.detection_methods = json.dumps(result['detection_methods'])
        scan.features_detected = json.dumps(result['features'])
        scan.ip_address = request.remote_addr
        scan.user_agent = request.headers.get('User-Agent')
        db.session.add(scan)
        db.session.commit()

        return render_template('scan_certificate.html',
                               result=result,
                               domain=domain)

    return render_template('scan_certificate.html')


@app.route('/scan-history')
@login_required
def scan_history():
    page = request.args.get('page', 1, type=int)

    # Admin can see all scans, secondary users only their own
    if current_user.is_admin:
        scans = ScanHistory.query.order_by(
            ScanHistory.scan_time.desc()).paginate(page=page,
                                                   per_page=20,
                                                   error_out=False)
    else:
        scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(
            ScanHistory.scan_time.desc()).paginate(page=page,
                                                   per_page=20,
                                                   error_out=False)

    return render_template('scan_history.html', scans=scans)


@app.route('/education')
def education():
    return render_template('education.html')


@app.route('/profile')
@login_required
def profile():
    user_reports = PhishingReport.query.filter_by(
        user_id=current_user.id).order_by(
            PhishingReport.created_at.desc()).all()
    return render_template('profile.html', reports=user_reports)


@app.route('/test-password-change')
@login_required
def test_password_change():
    return render_template('test_password_change.html')


@app.route('/download-report')
@login_required
def download_report():
    # Generate enhanced professional PDF report
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.darkblue,
        alignment=TA_CENTER
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.darkblue,
        borderWidth=1,
        borderColor=colors.darkblue,
        borderPadding=5
    )
    
    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Heading3'],
        fontSize=14,
        spaceAfter=8,
        textColor=colors.darkred
    )

    # Header with logo placeholder and title
    story.append(Paragraph("PhishShield Pro", title_style))
    story.append(Paragraph(f"Security Analysis Report for {current_user.username}", subtitle_style))
    story.append(Spacer(1, 20))

    # Report metadata
    report_info = f"""
    <b>Report Generated:</b> {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}<br/>
    <b>User Account:</b> {current_user.username}<br/>
    <b>Email:</b> {current_user.email}<br/>
    <b>Account Created:</b> {current_user.created_at.strftime('%B %d, %Y')}<br/>
    <b>Report Type:</b> Comprehensive Scan History Analysis
    """
    story.append(Paragraph(report_info, styles['Normal']))
    story.append(Spacer(1, 20))

    # Get user's scan history
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(
        ScanHistory.scan_time.desc()).all()

    if scans:
        # Executive Summary
        story.append(Paragraph("Executive Summary", header_style))
        
        # Calculate statistics
        total_scans = len(scans)
        scan_types = Counter([scan.scan_type for scan in scans])
        results = Counter([scan.result for scan in scans])
        
        # Date range
        oldest_scan = min(scans, key=lambda x: x.scan_time)
        newest_scan = max(scans, key=lambda x: x.scan_time)
        
        # Threat statistics
        phishing_count = results.get('phishing', 0)
        suspicious_count = results.get('suspicious', 0)
        safe_count = results.get('safe', 0)
        threat_percentage = ((phishing_count + suspicious_count) / total_scans * 100) if total_scans > 0 else 0
        
        # Average confidence
        confidences = [scan.confidence for scan in scans if scan.confidence is not None]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0
        
        summary_text = f"""
        This report provides a comprehensive analysis of your scanning activity from 
        {oldest_scan.scan_time.strftime('%B %d, %Y')} to {newest_scan.scan_time.strftime('%B %d, %Y')}.
        <br/><br/>
        <b>Key Findings:</b><br/>
        • Total scans performed: {total_scans}<br/>
        • Threats detected: {phishing_count + suspicious_count} ({threat_percentage:.1f}% of all scans)<br/>
        • Average detection confidence: {avg_confidence:.1%}<br/>
        • Most common scan type: {scan_types.most_common(1)[0][0].title()}<br/>
        • Security status: {'HIGH RISK' if threat_percentage > 20 else 'MODERATE RISK' if threat_percentage > 10 else 'LOW RISK'}
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Scan Statistics Table
        story.append(Paragraph("Scan Statistics Overview", header_style))
        
        stats_data = [
            ['Metric', 'Value', 'Percentage'],
            ['Total Scans', str(total_scans), '100%'],
            ['Safe Results', str(safe_count), f'{(safe_count/total_scans*100):.1f}%'],
            ['Suspicious Results', str(suspicious_count), f'{(suspicious_count/total_scans*100):.1f}%'],
            ['Phishing Detected', str(phishing_count), f'{(phishing_count/total_scans*100):.1f}%'],
        ]
        
        # Add scan type breakdown
        for scan_type, count in scan_types.most_common():
            stats_data.append([f'{scan_type.title()} Scans', str(count), f'{(count/total_scans*100):.1f}%'])
        
        stats_table = Table(stats_data, colWidths=[2*inch, 1*inch, 1*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        # Threat Analysis Section
        if phishing_count > 0 or suspicious_count > 0:
            story.append(Paragraph("Threat Analysis", header_style))
            
            threat_analysis = f"""
            <b>Security Alert:</b> {phishing_count + suspicious_count} potential threats detected.<br/><br/>
            
            <b>Threat Breakdown:</b><br/>
            • Confirmed Phishing: {phishing_count} incidents<br/>
            • Suspicious Content: {suspicious_count} incidents<br/><br/>
            
            <b>Recommendations:</b><br/>
            • Review all flagged content carefully before interaction<br/>
            • Enable real-time protection in your browser<br/>
            • Keep your security awareness training up to date<br/>
            • Report any false positives to improve detection accuracy
            """
            story.append(Paragraph(threat_analysis, styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Recent Activity (Last 10 scans)
        story.append(Paragraph("Recent Scanning Activity", header_style))
        
        recent_scans = scans[:10]  # Already sorted by scan_time desc
        recent_data = [['Date & Time', 'Type', 'Content Preview', 'Result', 'Confidence']]
        
        for scan in recent_scans:
            # Color code results
            result_color = 'red' if scan.result == 'phishing' else 'orange' if scan.result == 'suspicious' else 'green'
            content_preview = scan.content[:40] + '...' if len(scan.content) > 40 else scan.content
            
            recent_data.append([
                scan.scan_time.strftime('%m/%d/%Y\n%H:%M:%S'),
                scan.scan_type.upper(),
                content_preview,
                scan.result.upper(),
                f"{scan.confidence:.1%}" if scan.confidence else 'N/A'
            ])
        
        recent_table = Table(recent_data, colWidths=[1.2*inch, 0.8*inch, 2.5*inch, 0.8*inch, 0.7*inch])
        recent_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        story.append(recent_table)
        
        # Add page break before detailed history
        if len(scans) > 10:
            story.append(PageBreak())
            story.append(Paragraph("Complete Scan History", header_style))
            
            # Complete history table
            all_data = [['#', 'Date & Time', 'Type', 'Content', 'Result', 'Confidence', 'IP Address']]
            
            for i, scan in enumerate(scans, 1):
                all_data.append([
                    str(i),
                    scan.scan_time.strftime('%m/%d/%Y %H:%M'),
                    scan.scan_type.capitalize(),
                    scan.content[:60] + '...' if len(scan.content) > 60 else scan.content,
                    scan.result.capitalize(),
                    f"{scan.confidence:.1%}" if scan.confidence else 'N/A',
                    scan.ip_address or 'N/A'
                ])
            
            complete_table = Table(all_data, colWidths=[0.3*inch, 1*inch, 0.7*inch, 2.2*inch, 0.7*inch, 0.7*inch, 1.1*inch])
            complete_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 7),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            story.append(complete_table)
        
        # Footer
        story.append(Spacer(1, 30))
        footer_text = f"""
        <b>Report Footer:</b><br/>
        This report was automatically generated by PhishShield Pro on {datetime.now().strftime('%B %d, %Y')}.<br/>
        For questions about this report, please contact your system administrator.<br/>
        <i>PhishShield Pro - Advanced Phishing Detection & Prevention</i>
        """
        story.append(Paragraph(footer_text, styles['Normal']))
        
    else:
        # No data message
        no_data_msg = """
        <b>No Scanning Activity Found</b><br/><br/>
        This account has no recorded scanning activity. To generate meaningful reports:
        <br/><br/>
        • Start scanning URLs, emails, or HTML files<br/>
        • Use the browser extension for automatic protection<br/>
        • Check back after performing some scans<br/><br/>
        <i>Your security is our priority. Start scanning today!</i>
        """
        story.append(Paragraph(no_data_msg, styles['Normal']))

    # Build the PDF
    doc.build(story)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'PhishShield_Professional_Report_{current_user.username}_{datetime.now().strftime("%Y%m%d_%H%M")}.pdf',
        mimetype='application/pdf')


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))

    # Get admin statistics
    total_users = User.query.count()
    total_scans = ScanHistory.query.count()
    total_reports = PhishingReport.query.count()
    total_datasets = MLDataset.query.count()

    # Recent activity
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_scans = ScanHistory.query.order_by(
        ScanHistory.scan_time.desc()).limit(10).all()

    stats = {
        'total_users': total_users,
        'total_scans': total_scans,
        'total_reports': total_reports,
        'total_datasets': total_datasets
    }

    return render_template('admin.html',
                           stats=stats,
                           recent_users=recent_users,
                           recent_scans=recent_scans)


@app.route('/admin/populate-datasets', methods=['POST'])
@login_required
def populate_datasets():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))

    try:
        from utils.dataset_manager import DatasetManager
        manager = DatasetManager()
        manager.populate_database()
        flash('Datasets populated successfully with 6000+ records!', 'success')
    except Exception as e:
        flash(f'Error populating datasets: {str(e)}', 'error')

    return redirect(url_for('admin'))


@app.route('/report-phishing', methods=['POST'])
@login_required
def report_phishing():
    try:
        # Debug CSRF token
        csrf_token = request.form.get('csrf_token')
        print(f"DEBUG: CSRF token received: {csrf_token}")
        print(f"DEBUG: Form data: {dict(request.form)}")
        
        url = request.form['url'].strip()
        description = request.form.get('description', '').strip()

        if not url:
            flash('URL is required', 'error')
            return redirect(url_for('profile'))

        # Create new report
        report = PhishingReport()
        report.user_id = current_user.id
        report.content = url  # Store the URL in the content field
        report.report_type = 'url'  # Set report type as 'url'
        report.description = description
        db.session.add(report)
        db.session.commit()

        flash('Thank you for reporting! We will investigate this URL.',
              'success')
        return redirect(url_for('profile'))
    except Exception as e:
        print(f"DEBUG: Error in report_phishing: {e}")
        flash(f'Error processing report: {str(e)}', 'error')
        return redirect(url_for('profile'))


@app.route('/api/scan-url', methods=['POST'])
@login_required
def api_scan_url():
    """API endpoint for authenticated users"""
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # Analyze the URL
    result = analyze_url(url)

    # Save scan history
    scan = ScanHistory()
    scan.user_id = current_user.id
    scan.scan_type = 'url'
    scan.content = url
    scan.result = result['result']
    scan.confidence = result['confidence']
    scan.detection_methods = json.dumps(result['detection_methods'])
    scan.features_detected = json.dumps(result['features'])
    scan.ip_address = request.remote_addr
    scan.user_agent = request.headers.get('User-Agent')
    db.session.add(scan)
    db.session.commit()

    return jsonify(result)


@app.route('/api/extension/scan-url', methods=['POST'])
def api_extension_scan_url():
    """Public API endpoint for browser extension"""
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # Analyze the URL
    result = analyze_url(url)

    # For extension, we don't save to scan history since user might not be logged in
    # But we can add basic logging for security monitoring
    print(f"Extension scan: {url} -> {result['result']} ({result['confidence']:.2f})")

    return jsonify(result)


@app.route('/api/password-strength', methods=['POST'])
def api_password_strength():
    """API endpoint to check password strength"""
    data = request.get_json()
    password = data.get('password', '')

    strength = {
        'is_strong': User.is_strong_password(password),
        'length': len(password) >= 8,
        'has_upper': bool(re.search(r'[A-Z]', password)),
        'has_lower': bool(re.search(r'[a-z]', password)),
        'has_digit': bool(re.search(r'\d', password)),
        'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }

    return jsonify(strength)


@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    """API endpoint to change user password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        # Validate input
        if not current_password or not new_password or not confirm_password:
            app.logger.warning(f"Password change attempt with missing fields by user {current_user.username} from IP {request.remote_addr}")
            return jsonify({
                'success': False,
                'message': 'All fields are required'
            }), 400
        
        # Verify current password
        if not current_user.check_password(current_password):
            app.logger.warning(f"Failed password change attempt - incorrect current password by user {current_user.username} from IP {request.remote_addr}")
            return jsonify({
                'success': False,
                'message': 'Current password is incorrect'
            }), 400
        
        # Check if new passwords match
        if new_password != confirm_password:
            return jsonify({
                'success': False,
                'message': 'New passwords do not match'
            }), 400
        
        # Check if new password is different from current
        if current_user.check_password(new_password):
            return jsonify({
                'success': False,
                'message': 'New password must be different from current password'
            }), 400
        
        # Validate new password strength
        if not User.is_strong_password(new_password):
            return jsonify({
                'success': False,
                'message': 'New password does not meet strength requirements. Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character.'
            }), 400
        
        # Update password
        current_user.set_password(new_password)
        db.session.commit()
        
        # Log successful password change
        app.logger.info(f"Password successfully changed for user {current_user.username} from IP {request.remote_addr}")
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })
        
    except ValueError as e:
        app.logger.error(f"Password change validation error for user {current_user.username}: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400
    except Exception as e:
        app.logger.error(f"Password change error for user {current_user.username}: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'An error occurred while changing password. Please try again.'
        }), 500


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
