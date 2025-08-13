
import re
import json
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import tldextract
import whois
from datetime import datetime
import requests
import ssl
import socket

class PhishingDetector:
    def __init__(self):
        self.phishing_keywords = [
            'verify', 'account', 'suspended', 'confirm', 'update', 'secure',
            'urgent', 'immediate', 'click', 'winner', 'congratulations',
            'prize', 'lottery', 'inheritance', 'prince', 'nigeria',
            'paypal', 'amazon', 'apple', 'microsoft', 'google',
            'login', 'signin', 'verification', 'banking'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.work', '.party', '.science', '.date', '.racing'
        ]
        
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'ebay.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com'
        ]
    
    def detect_url_phishing(self, url):
        """Comprehensive URL phishing detection with detailed explanations"""
        detection_results = {
            'result': 'safe',
            'confidence': 0.8,
            'methods_used': [],
            'detailed_analysis': [],
            'risk_factors': [],
            'safe_indicators': []
        }
        
        risk_score = 0
        
        try:
            parsed_url = urlparse(url)
            domain_info = tldextract.extract(url)
            
            # Rule 1: Check for IP address instead of domain
            ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            if re.match(ip_pattern, parsed_url.hostname or ''):
                risk_score += 25
                detection_results['risk_factors'].append({
                    'rule': 'IP Address Usage',
                    'description': 'Uses IP address instead of domain name - common in phishing',
                    'severity': 'high',
                    'detected': parsed_url.hostname
                })
                detection_results['methods_used'].append('IP Address Detection')
            else:
                detection_results['safe_indicators'].append({
                    'rule': 'Domain Name Usage',
                    'description': 'Uses proper domain name instead of IP address'
                })
            
            # Rule 2: Check protocol security
            if parsed_url.scheme != 'https':
                risk_score += 15
                detection_results['risk_factors'].append({
                    'rule': 'Insecure Protocol',
                    'description': 'Uses HTTP instead of HTTPS - data not encrypted',
                    'severity': 'medium',
                    'detected': parsed_url.scheme
                })
                detection_results['methods_used'].append('Protocol Analysis')
            else:
                detection_results['safe_indicators'].append({
                    'rule': 'Secure Protocol',
                    'description': 'Uses HTTPS for encrypted communication'
                })
            
            # Rule 3: Check URL length
            if len(url) > 100:
                risk_score += 10
                detection_results['risk_factors'].append({
                    'rule': 'Excessive URL Length',
                    'description': 'Very long URLs are often used to hide malicious intent',
                    'severity': 'low',
                    'detected': f'{len(url)} characters'
                })
                detection_results['methods_used'].append('URL Length Analysis')
            
            # Rule 4: Check for suspicious TLD
            tld = domain_info.suffix
            if tld in self.suspicious_tlds:
                risk_score += 20
                detection_results['risk_factors'].append({
                    'rule': 'Suspicious TLD',
                    'description': 'Uses top-level domain commonly associated with malicious sites',
                    'severity': 'medium',
                    'detected': tld
                })
                detection_results['methods_used'].append('TLD Analysis')
            
            # Rule 5: Check subdomain count
            subdomain_count = len(domain_info.subdomain.split('.')) if domain_info.subdomain else 0
            if subdomain_count > 3:
                risk_score += 15
                detection_results['risk_factors'].append({
                    'rule': 'Excessive Subdomains',
                    'description': 'Multiple subdomains can indicate subdomain abuse',
                    'severity': 'medium',
                    'detected': f'{subdomain_count} subdomains'
                })
                detection_results['methods_used'].append('Subdomain Analysis')
            
            # Rule 6: Check for phishing keywords in domain
            domain_keywords = self._check_phishing_keywords(domain_info.domain + '.' + domain_info.suffix)
            if domain_keywords:
                risk_score += len(domain_keywords) * 10
                detection_results['risk_factors'].append({
                    'rule': 'Phishing Keywords in Domain',
                    'description': 'Domain contains words commonly used in phishing attacks',
                    'severity': 'high',
                    'detected': ', '.join(domain_keywords)
                })
                detection_results['methods_used'].append('Keyword Analysis')
            
            # Rule 7: Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link']
            if any(shortener in url.lower() for shortener in shorteners):
                risk_score += 20
                detection_results['risk_factors'].append({
                    'rule': 'URL Shortener',
                    'description': 'URL shorteners can hide the real destination',
                    'severity': 'medium',
                    'detected': 'URL shortening service detected'
                })
                detection_results['methods_used'].append('URL Shortener Detection')
            
            # Rule 8: Check for suspicious characters
            suspicious_chars = ['@', '%', '&', '=', '+']
            found_chars = [char for char in suspicious_chars if char in url]
            if len(found_chars) > 2:
                risk_score += 10
                detection_results['risk_factors'].append({
                    'rule': 'Suspicious Characters',
                    'description': 'Contains multiple suspicious characters that may indicate obfuscation',
                    'severity': 'low',
                    'detected': ', '.join(found_chars)
                })
                detection_results['methods_used'].append('Character Analysis')
            
            # Rule 9: Check domain age (simplified check)
            try:
                domain_age = self._check_domain_age(domain_info.domain + '.' + domain_info.suffix)
                if domain_age and domain_age < 30:  # Less than 30 days
                    risk_score += 25
                    detection_results['risk_factors'].append({
                        'rule': 'New Domain',
                        'description': 'Very new domain registration - common in phishing campaigns',
                        'severity': 'high',
                        'detected': f'{domain_age} days old'
                    })
                    detection_results['methods_used'].append('Domain Age Analysis')
                elif domain_age and domain_age > 365:
                    detection_results['safe_indicators'].append({
                        'rule': 'Established Domain',
                        'description': f'Domain registered for {domain_age} days - indicates legitimacy'
                    })
            except:
                pass
            
            # Rule 10: Check for legitimate domain spoofing
            for legit_domain in self.legitimate_domains:
                if self._is_similar_domain(domain_info.domain + '.' + domain_info.suffix, legit_domain):
                    risk_score += 30
                    detection_results['risk_factors'].append({
                        'rule': 'Domain Spoofing',
                        'description': f'Domain appears to mimic legitimate site: {legit_domain}',
                        'severity': 'high',
                        'detected': f'Similar to {legit_domain}'
                    })
                    detection_results['methods_used'].append('Domain Spoofing Detection')
                    break
            
        except Exception as e:
            detection_results['detailed_analysis'].append(f"Analysis error: {str(e)}")
        
        # Determine final result
        if risk_score >= 50:
            detection_results['result'] = 'phishing'
            detection_results['confidence'] = min(0.95, 0.5 + (risk_score / 100))
        elif risk_score >= 25:
            detection_results['result'] = 'suspicious'
            detection_results['confidence'] = 0.7
        else:
            detection_results['result'] = 'safe'
            detection_results['confidence'] = max(0.8, 1.0 - (risk_score / 100))
        
        detection_results['risk_score'] = risk_score
        detection_results['detailed_analysis'] = self._generate_detailed_analysis(detection_results)
        
        return detection_results
    
    def detect_email_phishing(self, email_content):
        """Enhanced email phishing detection with detailed analysis"""
        detection_results = {
            'result': 'safe',
            'confidence': 0.8,
            'methods_used': [],
            'detailed_analysis': [],
            'risk_factors': [],
            'safe_indicators': []
        }
        
        risk_score = 0
        
        try:
            # Rule 1: Check for urgent language
            urgent_phrases = [
                'urgent', 'immediate action', 'act now', 'expires today',
                'limited time', 'don\'t wait', 'hurry', 'final notice'
            ]
            found_urgent = [phrase for phrase in urgent_phrases if phrase.lower() in email_content.lower()]
            if found_urgent:
                risk_score += len(found_urgent) * 10
                detection_results['risk_factors'].append({
                    'rule': 'Urgent Language',
                    'description': 'Uses urgent language to pressure quick action',
                    'severity': 'medium',
                    'detected': ', '.join(found_urgent)
                })
                detection_results['methods_used'].append('Language Analysis')
            
            # Rule 2: Check for generic greetings
            generic_greetings = ['dear customer', 'dear user', 'dear sir/madam', 'valued customer']
            if any(greeting in email_content.lower() for greeting in generic_greetings):
                risk_score += 15
                detection_results['risk_factors'].append({
                    'rule': 'Generic Greeting',
                    'description': 'Uses generic greeting instead of personalized name',
                    'severity': 'medium',
                    'detected': 'Generic greeting found'
                })
                detection_results['methods_used'].append('Greeting Analysis')
            
            # Rule 3: Check for suspicious links
            url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            urls = re.findall(url_pattern, email_content)
            
            suspicious_url_count = 0
            for url in urls:
                url_result = self.detect_url_phishing(url if url.startswith('http') else 'http://' + url)
                if url_result['result'] != 'safe':
                    suspicious_url_count += 1
            
            if suspicious_url_count > 0:
                risk_score += suspicious_url_count * 20
                detection_results['risk_factors'].append({
                    'rule': 'Suspicious Links',
                    'description': f'Contains {suspicious_url_count} suspicious links',
                    'severity': 'high',
                    'detected': f'{suspicious_url_count} suspicious URLs'
                })
                detection_results['methods_used'].append('Link Analysis')
            
            # Rule 4: Check for personal information requests
            personal_requests = [
                'social security', 'ssn', 'password', 'pin', 'credit card',
                'bank account', 'routing number', 'date of birth', 'mother\'s maiden name'
            ]
            found_requests = [req for req in personal_requests if req in email_content.lower()]
            if found_requests:
                risk_score += len(found_requests) * 15
                detection_results['risk_factors'].append({
                    'rule': 'Personal Information Request',
                    'description': 'Requests sensitive personal information',
                    'severity': 'high',
                    'detected': ', '.join(found_requests)
                })
                detection_results['methods_used'].append('Information Request Analysis')
            
            # Rule 5: Check for poor grammar/spelling
            common_mistakes = [
                'recieve', 'seperate', 'occured', 'thier', 'definately',
                'accomodate', 'acheive', 'arguement', 'calender', 'cemetary'
            ]
            grammar_issues = [mistake for mistake in common_mistakes if mistake in email_content.lower()]
            if len(grammar_issues) >= 2:
                risk_score += 10
                detection_results['risk_factors'].append({
                    'rule': 'Poor Grammar/Spelling',
                    'description': 'Contains multiple spelling errors - common in phishing',
                    'severity': 'low',
                    'detected': f'{len(grammar_issues)} spelling errors'
                })
                detection_results['methods_used'].append('Grammar Analysis')
            
        except Exception as e:
            detection_results['detailed_analysis'].append(f"Analysis error: {str(e)}")
        
        # Determine final result
        if risk_score >= 50:
            detection_results['result'] = 'phishing'
            detection_results['confidence'] = min(0.95, 0.5 + (risk_score / 100))
        elif risk_score >= 25:
            detection_results['result'] = 'suspicious'
            detection_results['confidence'] = 0.7
        else:
            detection_results['result'] = 'safe'
            detection_results['confidence'] = max(0.8, 1.0 - (risk_score / 100))
        
        detection_results['risk_score'] = risk_score
        detection_results['detailed_analysis'] = self._generate_detailed_analysis(detection_results)
        
        return detection_results
    
    def detect_html_phishing(self, html_content):
        """Enhanced HTML phishing detection with detailed analysis"""
        detection_results = {
            'result': 'safe',
            'confidence': 0.8,
            'methods_used': [],
            'detailed_analysis': [],
            'risk_factors': [],
            'safe_indicators': []
        }
        
        risk_score = 0
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Rule 1: Check for suspicious forms
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', '').lower()
                
                # Check form action
                if action and not action.startswith('#') and not action.startswith('/'):
                    parsed_action = urlparse(action)
                    if parsed_action.netloc and not self._is_legitimate_domain(parsed_action.netloc):
                        risk_score += 25
                        detection_results['risk_factors'].append({
                            'rule': 'Suspicious Form Action',
                            'description': 'Form submits to external suspicious domain',
                            'severity': 'high',
                            'detected': action
                        })
                        detection_results['methods_used'].append('Form Analysis')
                
                # Check for password fields
                password_fields = form.find_all('input', {'type': 'password'})
                if password_fields:
                    risk_score += 15
                    detection_results['risk_factors'].append({
                        'rule': 'Password Field Present',
                        'description': 'Contains password input field - potential credential harvesting',
                        'severity': 'medium',
                        'detected': f'{len(password_fields)} password fields'
                    })
                    detection_results['methods_used'].append('Input Field Analysis')
            
            # Rule 2: Check for suspicious scripts
            scripts = soup.find_all('script')
            for script in scripts:
                src = script.get('src', '')
                if src:
                    parsed_src = urlparse(src)
                    if parsed_src.netloc and not self._is_legitimate_domain(parsed_src.netloc):
                        risk_score += 20
                        detection_results['risk_factors'].append({
                            'rule': 'Suspicious External Script',
                            'description': 'Loads scripts from suspicious external domain',
                            'severity': 'high',
                            'detected': src
                        })
                        detection_results['methods_used'].append('Script Analysis')
                
                # Check for obfuscated scripts
                script_content = script.string or ''
                if len(script_content) > 1000 and (script_content.count('eval(') > 0 or 
                                                  script_content.count('unescape(') > 0):
                    risk_score += 15
                    detection_results['risk_factors'].append({
                        'rule': 'Obfuscated JavaScript',
                        'description': 'Contains potentially obfuscated JavaScript code',
                        'severity': 'medium',
                        'detected': 'Obfuscated code patterns'
                    })
                    detection_results['methods_used'].append('Code Obfuscation Analysis')
            
            # Rule 3: Check for hidden elements
            hidden_elements = soup.find_all(['input', 'div', 'span'], {'style': lambda x: x and 'display:none' in x.replace(' ', '')})
            hidden_elements.extend(soup.find_all(['input'], {'type': 'hidden'}))
            
            if len(hidden_elements) > 5:
                risk_score += 10
                detection_results['risk_factors'].append({
                    'rule': 'Excessive Hidden Elements',
                    'description': 'Contains many hidden elements - potential for data exfiltration',
                    'severity': 'low',
                    'detected': f'{len(hidden_elements)} hidden elements'
                })
                detection_results['methods_used'].append('Hidden Element Analysis')
            
            # Rule 4: Check for suspicious iframes
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                src = iframe.get('src', '')
                if src:
                    parsed_src = urlparse(src)
                    if parsed_src.netloc and not self._is_legitimate_domain(parsed_src.netloc):
                        risk_score += 30
                        detection_results['risk_factors'].append({
                            'rule': 'Suspicious Iframe',
                            'description': 'Contains iframe from suspicious external source',
                            'severity': 'high',
                            'detected': src
                        })
                        detection_results['methods_used'].append('Iframe Analysis')
            
            # Rule 5: Check title and meta tags for deception
            title = soup.find('title')
            if title and title.string:
                title_text = title.string.lower()
                brand_keywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook']
                for brand in brand_keywords:
                    if brand in title_text and not self._is_legitimate_brand_context(html_content, brand):
                        risk_score += 25
                        detection_results['risk_factors'].append({
                            'rule': 'Brand Impersonation in Title',
                            'description': f'Title impersonates {brand} brand',
                            'severity': 'high',
                            'detected': f'Potential {brand} impersonation'
                        })
                        detection_results['methods_used'].append('Brand Impersonation Analysis')
                        break
        
        except Exception as e:
            detection_results['detailed_analysis'].append(f"Analysis error: {str(e)}")
        
        # Determine final result
        if risk_score >= 50:
            detection_results['result'] = 'phishing'
            detection_results['confidence'] = min(0.95, 0.5 + (risk_score / 100))
        elif risk_score >= 25:
            detection_results['result'] = 'suspicious'
            detection_results['confidence'] = 0.7
        else:
            detection_results['result'] = 'safe'
            detection_results['confidence'] = max(0.8, 1.0 - (risk_score / 100))
        
        detection_results['risk_score'] = risk_score
        detection_results['detailed_analysis'] = self._generate_detailed_analysis(detection_results)
        
        return detection_results
    
    def _check_phishing_keywords(self, text):
        """Check for phishing keywords in text"""
        found_keywords = []
        text_lower = text.lower()
        for keyword in self.phishing_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        return found_keywords
    
    def _check_domain_age(self, domain):
        """Check domain registration age in days"""
        try:
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                age = (datetime.now() - creation_date).days
                return age
        except:
            pass
        return None
    
    def _is_similar_domain(self, domain1, domain2):
        """Check if domains are suspiciously similar"""
        # Simple similarity check - can be enhanced with edit distance
        domain1_clean = domain1.replace('www.', '').lower()
        domain2_clean = domain2.replace('www.', '').lower()
        
        # Check for common substitutions
        substitutions = {'0': 'o', '1': 'l', '3': 'e', '5': 's', '@': 'a'}
        
        for orig, sub in substitutions.items():
            if domain1_clean.replace(orig, sub) == domain2_clean:
                return True
            if domain1_clean.replace(sub, orig) == domain2_clean:
                return True
        
        # Check for added/removed characters
        if len(domain1_clean) == len(domain2_clean) + 1:
            for i in range(len(domain1_clean)):
                if domain1_clean[:i] + domain1_clean[i+1:] == domain2_clean:
                    return True
        
        return False
    
    def _is_legitimate_domain(self, domain):
        """Check if domain is known to be legitimate"""
        return any(legit in domain.lower() for legit in self.legitimate_domains)
    
    def _is_legitimate_brand_context(self, html_content, brand):
        """Check if brand mention is in legitimate context"""
        # This is a simplified check - in practice, you'd want more sophisticated analysis
        legitimate_indicators = [
            f'© {brand}', f'copyright {brand}', f'{brand} inc', f'{brand} corporation'
        ]
        return any(indicator.lower() in html_content.lower() for indicator in legitimate_indicators)
    
    def _generate_detailed_analysis(self, results):
        """Generate human-readable detailed analysis"""
        analysis = []
        
        analysis.append(f"Overall Assessment: {results['result'].upper()}")
        analysis.append(f"Confidence Level: {results['confidence']:.1%}")
        analysis.append(f"Risk Score: {results.get('risk_score', 0)}/100")
        
        if results['risk_factors']:
            analysis.append("\nRisk Factors Detected:")
            for factor in results['risk_factors']:
                severity_icon = {"high": "🔴", "medium": "🟡", "low": "🟠"}.get(factor['severity'], "⚪")
                analysis.append(f"  {severity_icon} {factor['rule']}: {factor['description']}")
        
        if results['safe_indicators']:
            analysis.append("\nSafe Indicators:")
            for indicator in results['safe_indicators']:
                analysis.append(f"  ✅ {indicator['rule']}: {indicator['description']}")
        
        analysis.append(f"\nDetection Methods Used: {', '.join(results['methods_used'])}")
        
        return analysis


# Global detector instance
detector = PhishingDetector()

def analyze_url(url):
    """Analyze URL for phishing indicators"""
    result = detector.detect_url_phishing(url)
    
    # Convert to format expected by routes
    return {
        'result': result['result'],
        'confidence': result['confidence'],
        'detection_methods': result['methods_used'],
        'features': {
            'risk_factors': len(result['risk_factors']),
            'safe_indicators': len(result['safe_indicators']),
            'risk_score': result.get('risk_score', 0)
        },
        'details': {
            'analysis': result['detailed_analysis'],
            'risk_factors': result['risk_factors'],
            'safe_indicators': result['safe_indicators']
        },
        'method': 'rule-based'
    }

def analyze_email(email_content):
    """Analyze email content for phishing indicators"""
    result = detector.detect_email_phishing(email_content)
    
    # Convert to format expected by routes
    return {
        'result': result['result'],
        'confidence': result['confidence'],
        'detection_methods': result['methods_used'],
        'features': {
            'risk_factors': len(result['risk_factors']),
            'safe_indicators': len(result['safe_indicators']),
            'risk_score': result.get('risk_score', 0)
        },
        'details': {
            'analysis': result['detailed_analysis'],
            'risk_factors': result['risk_factors'],
            'safe_indicators': result['safe_indicators']
        },
        'method': 'rule-based'
    }

def analyze_html_file(html_content, filename=None):
    """Analyze HTML file content for phishing indicators"""
    result = detector.detect_html_phishing(html_content)
    
    # Convert to format expected by routes
    return {
        'result': result['result'],
        'confidence': result['confidence'],
        'detection_methods': result['methods_used'],
        'features': {
            'risk_factors': len(result['risk_factors']),
            'safe_indicators': len(result['safe_indicators']),
            'risk_score': result.get('risk_score', 0),
            'filename': filename or 'uploaded_file.html'
        },
        'details': {
            'analysis': result['detailed_analysis'],
            'risk_factors': result['risk_factors'],
            'safe_indicators': result['safe_indicators']
        },
        'method': 'rule-based'
    }
