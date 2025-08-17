
import re
import tldextract
import whois
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import socket
import ssl

def extract_url_features(url):
    """
    Extract comprehensive features from URL for ML analysis
    """
    features = {}
    
    try:
        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Basic URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_signs'] = url.count('@')
        features['uses_https'] = url.startswith('https://')
        features['has_port'] = bool(parsed_url.port)
        
        # Domain features
        domain = f"{extracted.domain}.{extracted.suffix}"
        features['domain_length'] = len(domain)
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        
        # IP address detection
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['has_ip'] = bool(re.search(ip_pattern, parsed_url.netloc))
        
        # Path analysis
        features['path_length'] = len(parsed_url.path)
        features['path_depth'] = len([p for p in parsed_url.path.split('/') if p])
        
        # Query parameters
        query_params = parse_qs(parsed_url.query)
        features['num_query_params'] = len(query_params)
        
        # Suspicious keywords
        suspicious_keywords = [
            'login', 'secure', 'account', 'update', 'verify', 'banking',
            'paypal', 'amazon', 'microsoft', 'google', 'apple'
        ]
        features['has_suspicious_keywords'] = any(keyword in url.lower() for keyword in suspicious_keywords)
        
        # Domain age analysis
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                age_days = (datetime.now() - creation_date).days
                features['domain_age_days'] = age_days
                features['is_new_domain'] = age_days < 30
            else:
                features['domain_age_days'] = 0
                features['is_new_domain'] = True
        except:
            features['domain_age_days'] = 0
            features['is_new_domain'] = True
        
        # New ML features
        features['has_shortener'] = any(shortener in url.lower() for shortener in 
                                      ['bit.ly', 'tinyurl', 't.co', 'goo.gl'])
        features['num_special_chars'] = sum(url.count(char) for char in '!@#$%^&*()_+-=[]{}|;:,.<>?')
        features['has_redirect_chain'] = '@' in url or '//' in parsed_url.path
        
        # TLD analysis
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc']
        features['has_suspicious_tld'] = f".{extracted.suffix}" in suspicious_tlds
        
        # Certificate features (for HTTPS URLs)
        if url.startswith('https://'):
            try:
                context = ssl.create_default_context()
                with socket.create_connection((parsed_url.netloc, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed_url.netloc) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Certificate validity
                        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        features['cert_days_to_expire'] = (expiry_date - datetime.now()).days
                        features['cert_expired'] = expiry_date < datetime.now()
                        
                        # Self-signed check
                        subject = dict(x[0] for x in cert['subject'])
                        issuer = dict(x[0] for x in cert['issuer'])
                        features['cert_self_signed'] = subject.get('organizationName') == issuer.get('organizationName')
                        
            except:
                features['cert_days_to_expire'] = 0
                features['cert_expired'] = True
                features['cert_self_signed'] = True
        else:
            features['cert_days_to_expire'] = 0
            features['cert_expired'] = False
            features['cert_self_signed'] = False
        
    except Exception as e:
        # Set default values if extraction fails
        default_features = {
            'url_length': 0, 'num_dots': 0, 'num_hyphens': 0, 'num_underscores': 0,
            'num_slashes': 0, 'num_question_marks': 0, 'num_equal_signs': 0,
            'num_at_signs': 0, 'uses_https': False, 'has_port': False,
            'domain_length': 0, 'subdomain_count': 0, 'has_ip': False,
            'path_length': 0, 'path_depth': 0, 'num_query_params': 0,
            'has_suspicious_keywords': False, 'domain_age_days': 0,
            'is_new_domain': True, 'has_shortener': False, 'num_special_chars': 0,
            'has_redirect_chain': False, 'has_suspicious_tld': False,
            'cert_days_to_expire': 0, 'cert_expired': False, 'cert_self_signed': False
        }
        features.update(default_features)
    
    return features

def extract_email_features(email_content, email_headers=None):
    """
    Extract comprehensive features from email content for analysis
    Enhanced with advanced phishing detection indicators
    """
    features = {}
    
    try:
        from .rules_engine import rules_engine
        
        email_lower = email_content.lower()
        
        # Basic email features
        features['email_length'] = len(email_content)
        features['num_links'] = len(re.findall(r'http[s]?://[^\s]+', email_content))
        features['num_attachments'] = email_content.count('attachment')
        
        # Enhanced sender analysis using rules engine
        sender_analysis = rules_engine._analyze_email_sender(email_content, email_headers or {})
        features['sender_suspicious'] = sender_analysis['suspicious']
        features['sender_risk_score'] = sender_analysis['score']
        features['sender_severity'] = sender_analysis['severity']
        features['sender_details_count'] = len(sender_analysis['details'])
        
        # Header analysis (if headers provided)
        if email_headers:
            header_analysis = rules_engine._analyze_email_headers(email_headers)
            features['header_suspicious'] = header_analysis['suspicious']
            features['header_risk_score'] = header_analysis['score']
            features['header_missing_count'] = len([d for d in header_analysis['details'] if 'missing' in d.lower()])
        else:
            features['header_suspicious'] = False
            features['header_risk_score'] = 0
            features['header_missing_count'] = 0
        
        # Enhanced content pattern analysis
        content_analysis = rules_engine._analyze_email_content_patterns(email_content)
        features['content_suspicious'] = content_analysis['suspicious']
        features['content_risk_score'] = content_analysis['score']
        features['urgent_phrases_count'] = sum(1 for detail in content_analysis['details'] if 'urgent' in detail.lower())
        features['personal_info_requests'] = sum(1 for detail in content_analysis['details'] if 'personal info' in detail.lower())
        
        # BEC (Business Email Compromise) indicators
        bec_analysis = rules_engine._analyze_bec_indicators(email_content)
        features['bec_suspicious'] = bec_analysis['suspicious']
        features['bec_risk_score'] = bec_analysis['score']
        features['bec_indicators_count'] = sum(1 for detail in bec_analysis['details'] if 'bec indicators' in detail.lower())
        features['financial_requests'] = sum(1 for detail in bec_analysis['details'] if 'financial' in detail.lower())
        
        # URL analysis within email
        url_analysis = rules_engine._analyze_email_urls(email_content)
        features['email_urls_suspicious'] = url_analysis['suspicious']
        features['email_urls_risk_score'] = url_analysis['score']
        features['suspicious_urls_count'] = sum(1 for detail in url_analysis['details'] if 'suspicious urls' in detail.lower())
        
        # Enhanced attachment analysis
        attachment_analysis = rules_engine._analyze_email_attachments(email_content)
        features['attachments_suspicious'] = attachment_analysis['suspicious']
        features['attachments_risk_score'] = attachment_analysis['score']
        features['suspicious_attachments_count'] = sum(1 for detail in attachment_analysis['details'] if 'suspicious attachments' in detail.lower())
        
        # Legacy features for backward compatibility
        from_match = re.search(r'From:\s*([^<\n]+)', email_content, re.IGNORECASE)
        features['has_from_field'] = bool(from_match)
        
        if from_match:
            from_field = from_match.group(1).strip()
            features['from_display_name_length'] = len(from_field)
            
            # Check for executive titles
            exec_titles = ['ceo', 'president', 'director', 'manager', 'executive']
            features['has_exec_title'] = any(title in from_field.lower() for title in exec_titles)
        else:
            features['from_display_name_length'] = 0
            features['has_exec_title'] = False
        
        # Enhanced greeting analysis
        greeting_patterns = [
            r'dear\s+customer', r'dear\s+user', r'dear\s+member',
            r'hello\s+there', r'to\s+whom', r'dear\s+sir/madam',
            r'greetings', r'valued\s+customer'
        ]
        features['has_generic_greeting'] = any(re.search(pattern, email_lower) for pattern in greeting_patterns)
        
        # Enhanced urgency indicators
        urgent_phrases = [
            'urgent', 'immediate', 'expires', 'suspended', 'locked',
            'verify', 'confirm', 'update', 'act now', 'limited time',
            'expires today', 'final notice', 'account will be closed'
        ]
        features['urgency_score'] = sum(1 for phrase in urgent_phrases if phrase in email_lower)
        
        # Enhanced suspicious attachments
        suspicious_extensions = ['.exe', '.html', '.js', '.scr', '.zip', '.rar', '.bat', '.com', '.pif']
        features['has_suspicious_attachment'] = any(ext in email_lower for ext in suspicious_extensions)
        
        # Enhanced domain mismatch check
        reply_to_match = re.search(r'Reply-To:\s*[^@]+@([^\s>]+)', email_content, re.IGNORECASE)
        from_email_match = re.search(r'From:.*?([^@\s]+@[^>\s]+)', email_content, re.IGNORECASE)
        
        if reply_to_match and from_email_match:
            reply_domain = reply_to_match.group(1)
            from_domain = from_email_match.group(1).split('@')[1] if '@' in from_email_match.group(1) else ''
            features['domain_mismatch'] = reply_domain != from_domain
        else:
            features['domain_mismatch'] = False
        
        # Enhanced spelling errors check
        common_errors = [
            'recieve', 'seperate', 'teh', 'wont', 'cant', 'didnt',
            'youre', 'its', 'loose', 'there', 'your', 'definately'
        ]
        features['spelling_errors'] = sum(1 for error in common_errors if error in email_lower)
        
        # Additional advanced features
        features['has_html_content'] = '<html>' in email_lower or '<body>' in email_lower
        features['has_forms'] = '<form' in email_lower
        features['has_javascript'] = '<script' in email_lower
        features['has_external_images'] = bool(re.search(r'<img[^>]+src=["\']?https?://', email_content, re.IGNORECASE))
        
        # Calculate overall risk score
        risk_components = [
            features.get('sender_risk_score', 0),
            features.get('header_risk_score', 0),
            features.get('content_risk_score', 0),
            features.get('bec_risk_score', 0),
            features.get('email_urls_risk_score', 0),
            features.get('attachments_risk_score', 0)
        ]
        features['overall_risk_score'] = sum(risk_components)
        features['risk_level'] = 'high' if features['overall_risk_score'] > 50 else 'medium' if features['overall_risk_score'] > 25 else 'low'
        
    except Exception as e:
        # Default values with enhanced features
        features = {
            'email_length': 0, 'num_links': 0, 'num_attachments': 0,
            'has_from_field': False, 'from_display_name_length': 0,
            'has_exec_title': False, 'has_generic_greeting': False,
            'urgency_score': 0, 'has_suspicious_attachment': False,
            'domain_mismatch': False, 'spelling_errors': 0,
            # Enhanced features defaults
            'sender_suspicious': False, 'sender_risk_score': 0, 'sender_severity': 'low',
            'header_suspicious': False, 'header_risk_score': 0, 'header_missing_count': 0,
            'content_suspicious': False, 'content_risk_score': 0, 'urgent_phrases_count': 0,
            'bec_suspicious': False, 'bec_risk_score': 0, 'bec_indicators_count': 0,
            'email_urls_suspicious': False, 'email_urls_risk_score': 0, 'suspicious_urls_count': 0,
            'attachments_suspicious': False, 'attachments_risk_score': 0, 'suspicious_attachments_count': 0,
            'has_html_content': False, 'has_forms': False, 'has_javascript': False,
            'has_external_images': False, 'overall_risk_score': 0, 'risk_level': 'low'
        }
    
    return features

def extract_html_features(html_content, filename):
    """
    Extract features from HTML content for analysis
    """
    features = {}
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        html_lower = html_content.lower()
        
        # Basic HTML features
        features['html_length'] = len(html_content)
        features['num_forms'] = len(soup.find_all('form'))
        features['num_inputs'] = len(soup.find_all('input'))
        features['num_scripts'] = len(soup.find_all('script'))
        features['num_iframes'] = len(soup.find_all('iframe'))
        
        # Form analysis
        forms = soup.find_all('form')
        features['has_password_field'] = any(
            input_tag.get('type') == 'password' 
            for form in forms 
            for input_tag in form.find_all('input')
        )
        
        # Empty form actions
        features['has_empty_action'] = any(
            not form.get('action') or form.get('action') == '#' 
            for form in forms
        )
        
        # External form handlers
        external_actions = [
            form.get('action') for form in forms 
            if form.get('action') and form.get('action').startswith('http')
        ]
        features['num_external_forms'] = len(external_actions)
        
        # Favicon check
        features['has_favicon'] = bool(
            soup.find('link', rel='icon') or 
            soup.find('link', rel='shortcut icon') or 
            'favicon' in html_lower
        )
        
        # Title analysis
        title_tag = soup.find('title')
        if title_tag:
            title_text = title_tag.get_text().lower()
            brand_keywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'bank']
            features['impersonates_brand'] = any(brand in title_text for brand in brand_keywords)
            features['title_length'] = len(title_text)
        else:
            features['impersonates_brand'] = False
            features['title_length'] = 0
        
        # JavaScript analysis
        script_tags = soup.find_all('script')
        obfuscation_indicators = ['eval(', 'unescape(', 'fromcharcode', 'document.write(']
        features['has_obfuscated_js'] = any(
            any(indicator in str(script) for indicator in obfuscation_indicators)
            for script in script_tags
        )
        
        # External scripts
        external_scripts = [
            script.get('src') for script in script_tags 
            if script.get('src') and script.get('src').startswith('http')
        ]
        features['num_external_scripts'] = len(external_scripts)
        
        # Hidden elements
        hidden_elements = soup.find_all(style=re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden'))
        features['num_hidden_elements'] = len(hidden_elements)
        
        # Meta refresh redirect
        meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
        features['has_meta_refresh'] = bool(meta_refresh)
        
    except Exception as e:
        # Default values
        features = {
            'html_length': 0, 'num_forms': 0, 'num_inputs': 0, 'num_scripts': 0,
            'num_iframes': 0, 'has_password_field': False, 'has_empty_action': False,
            'num_external_forms': 0, 'has_favicon': True, 'impersonates_brand': False,
            'title_length': 0, 'has_obfuscated_js': False, 'num_external_scripts': 0,
            'num_hidden_elements': 0, 'has_meta_refresh': False
        }
    
    return features
