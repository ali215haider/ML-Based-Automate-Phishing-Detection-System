import re
import tldextract
import unicodedata
from urllib.parse import urlparse
from difflib import SequenceMatcher
import socket
import ssl
from datetime import datetime
import requests
from typing import Dict, List, Tuple, Any
from bs4 import BeautifulSoup

class IndustryStandardRulesEngine:
    """
    Industry-standard rules engine for phishing detection
    Implements comprehensive rule-based detection following cybersecurity best practices
    """
    
    def __init__(self):
        # Expanded suspicious TLDs based on industry reports
        self.suspicious_tlds = {
            'high_risk': ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.top', '.click', 
                         '.download', '.work', '.party', '.science', '.date', '.racing',
                         '.review', '.country', '.kim', '.cricket', '.faith', '.accountant'],
            'medium_risk': ['.info', '.biz', '.name', '.mobi', '.asia', '.tel', '.travel']
        }
        
        # Homograph attack patterns (IDN homograph)
        self.homograph_chars = {
            'a': ['а', 'ɑ', 'α', 'à', 'á', 'â', 'ã', 'ä', 'å'],
            'e': ['е', 'ε', 'è', 'é', 'ê', 'ë'],
            'o': ['о', 'ο', 'ò', 'ó', 'ô', 'õ', 'ö', '0'],
            'i': ['і', 'ι', 'ì', 'í', 'î', 'ï', '1', 'l'],
            'u': ['υ', 'ù', 'ú', 'û', 'ü'],
            'c': ['с', 'ç'],
            'p': ['р', 'ρ'],
            'h': ['һ'],
            'x': ['х', 'χ'],
            'y': ['у', 'γ', 'ý', 'ÿ'],
            'n': ['п'],
            'm': ['м'],
            'k': ['κ'],
            'b': ['в'],
            'd': ['ԁ'],
            'g': ['ց'],
            'j': ['ј'],
            'l': ['ӏ', '1', 'I'],
            's': ['ѕ', '$', '5'],
            't': ['т']
        }
        
        # Legitimate domains for spoofing detection
        self.legitimate_domains = {
            'financial': ['paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
                         'citibank.com', 'americanexpress.com', 'discover.com', 'capitalone.com'],
            'tech': ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
                    'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com', 'adobe.com'],
            'ecommerce': ['amazon.com', 'ebay.com', 'etsy.com', 'shopify.com', 'walmart.com',
                         'target.com', 'bestbuy.com', 'homedepot.com'],
            'social': ['facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com',
                      'snapchat.com', 'tiktok.com', 'youtube.com', 'pinterest.com']
        }
        
        # Suspicious keywords by category
        self.suspicious_keywords = {
            'urgency': ['urgent', 'immediate', 'expires', 'suspended', 'limited', 'act now',
                       'hurry', 'deadline', 'final notice', 'last chance'],
            'financial': ['verify account', 'update payment', 'billing', 'refund', 'tax',
                         'invoice', 'payment failed', 'card expired', 'unauthorized'],
            'security': ['security alert', 'suspicious activity', 'locked account', 'verify identity',
                        'confirm', 'validate', 'authenticate', 'secure'],
            'rewards': ['winner', 'congratulations', 'prize', 'lottery', 'inheritance',
                       'reward', 'bonus', 'gift', 'free', 'claim']
        }
        
        # URL shortener services
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link', 'ow.ly',
            'buff.ly', 'is.gd', 'tiny.cc', 'rebrand.ly', 'bl.ink', 'cutt.ly'
        ]
        
        # Suspicious ports
        self.suspicious_ports = [8080, 8443, 3000, 4000, 5000, 8000, 8888, 9000]
        
        # Email-specific patterns and indicators
        self.email_urgent_phrases = [
            'urgent', 'immediate action', 'act now', 'expires today', 'limited time',
            'don\'t wait', 'hurry', 'final notice', 'last chance', 'deadline',
            'time sensitive', 'expires soon', 'act immediately', 'respond now'
        ]
        
        self.email_generic_greetings = [
            'dear customer', 'dear user', 'dear sir/madam', 'valued customer',
            'dear member', 'hello there', 'to whom it may concern', 'greetings'
        ]
        
        self.email_personal_info_requests = [
            'social security', 'ssn', 'password', 'pin', 'credit card',
            'bank account', 'routing number', 'date of birth', 'mother\'s maiden name',
            'full name', 'address', 'phone number', 'driver\'s license'
        ]
        
        self.email_suspicious_attachments = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
            '.jar', '.zip', '.rar', '.7z', '.html', '.htm'
        ]
        
        self.email_bec_indicators = [
            'wire transfer', 'urgent payment', 'change bank details', 'new account',
            'confidential', 'invoice attached', 'payment request', 'bank transfer',
            'account update', 'vendor payment'
        ]
        
        self.email_executive_titles = [
            'ceo', 'president', 'director', 'manager', 'executive', 'vp',
            'vice president', 'chief', 'head of', 'senior', 'lead'
        ]
        
    def analyze_domain_rules(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive domain-based rule analysis
        """
        results = {
            'risk_score': 0,
            'rules_triggered': [],
            'domain_analysis': {},
            'homograph_detected': False,
            'spoofing_detected': False
        }
        
        try:
            parsed_url = urlparse(url)
            domain_info = tldextract.extract(url)
            full_domain = f"{domain_info.domain}.{domain_info.suffix}"
            
            # Rule 1: TLD Risk Assessment
            tld_risk = self._analyze_tld_risk(domain_info.suffix)
            if tld_risk['risk_level'] != 'low':
                results['risk_score'] += tld_risk['score']
                results['rules_triggered'].append({
                    'rule_id': 'TLD_RISK',
                    'rule_name': 'Suspicious TLD Analysis',
                    'severity': tld_risk['risk_level'],
                    'score': tld_risk['score'],
                    'description': f"TLD '.{domain_info.suffix}' is classified as {tld_risk['risk_level']} risk",
                    'detected_value': f".{domain_info.suffix}"
                })
            
            # Rule 2: Homograph Attack Detection
            homograph_result = self._detect_homograph_attack(full_domain)
            if homograph_result['detected']:
                results['homograph_detected'] = True
                results['risk_score'] += 35
                results['rules_triggered'].append({
                    'rule_id': 'HOMOGRAPH_ATTACK',
                    'rule_name': 'IDN Homograph Attack',
                    'severity': 'high',
                    'score': 35,
                    'description': 'Domain uses lookalike characters to mimic legitimate sites',
                    'detected_value': homograph_result['suspicious_chars'],
                    'potential_target': homograph_result['potential_target']
                })
            
            # Rule 3: Domain Spoofing Detection
            spoofing_result = self._detect_domain_spoofing(full_domain)
            if spoofing_result['detected']:
                results['spoofing_detected'] = True
                results['risk_score'] += spoofing_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'DOMAIN_SPOOFING',
                    'rule_name': 'Domain Spoofing',
                    'severity': 'high',
                    'score': spoofing_result['score'],
                    'description': f"Domain appears to mimic {spoofing_result['target_domain']}",
                    'detected_value': full_domain,
                    'target_domain': spoofing_result['target_domain'],
                    'similarity_score': spoofing_result['similarity']
                })
            
            # Rule 4: Subdomain Abuse Analysis
            subdomain_result = self._analyze_subdomain_abuse(domain_info)
            if subdomain_result['suspicious']:
                results['risk_score'] += subdomain_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'SUBDOMAIN_ABUSE',
                    'rule_name': 'Subdomain Abuse',
                    'severity': subdomain_result['severity'],
                    'score': subdomain_result['score'],
                    'description': subdomain_result['description'],
                    'detected_value': subdomain_result['subdomains']
                })
            
            # Rule 5: Domain Length Analysis
            if len(full_domain) > 50:
                score = min(20, (len(full_domain) - 50) // 5 * 5)
                results['risk_score'] += score
                results['rules_triggered'].append({
                    'rule_id': 'DOMAIN_LENGTH',
                    'rule_name': 'Excessive Domain Length',
                    'severity': 'medium',
                    'score': score,
                    'description': 'Unusually long domain name may indicate obfuscation',
                    'detected_value': f"{len(full_domain)} characters"
                })
            
            # Rule 6: Suspicious Character Patterns
            char_analysis = self._analyze_suspicious_characters(full_domain)
            if char_analysis['suspicious']:
                results['risk_score'] += char_analysis['score']
                results['rules_triggered'].append({
                    'rule_id': 'SUSPICIOUS_CHARS',
                    'rule_name': 'Suspicious Character Patterns',
                    'severity': char_analysis['severity'],
                    'score': char_analysis['score'],
                    'description': char_analysis['description'],
                    'detected_value': char_analysis['patterns']
                })
            
            results['domain_analysis'] = {
                'full_domain': full_domain,
                'domain': domain_info.domain,
                'subdomain': domain_info.subdomain,
                'suffix': domain_info.suffix,
                'domain_length': len(full_domain)
            }
            
        except Exception as e:
            results['error'] = f"Domain analysis error: {str(e)}"
        
        return results
    
    def _analyze_tld_risk(self, tld: str) -> Dict[str, Any]:
        """
        Analyze TLD risk level based on industry data
        """
        if tld in self.suspicious_tlds['high_risk']:
            return {'risk_level': 'high', 'score': 25}
        elif tld in self.suspicious_tlds['medium_risk']:
            return {'risk_level': 'medium', 'score': 10}
        else:
            return {'risk_level': 'low', 'score': 0}
    
    def _detect_homograph_attack(self, domain: str) -> Dict[str, Any]:
        """
        Detect IDN homograph attacks using lookalike characters
        """
        result = {
            'detected': False,
            'suspicious_chars': [],
            'potential_target': None
        }
        
        # Check for mixed scripts
        scripts = set()
        for char in domain:
            if char.isalpha():
                scripts.add(unicodedata.name(char, '').split()[0])
        
        if len(scripts) > 1:
            result['detected'] = True
            result['suspicious_chars'] = list(scripts)
        
        # Check for lookalike characters
        for normal_char, lookalikes in self.homograph_chars.items():
            for lookalike in lookalikes:
                if lookalike in domain:
                    result['detected'] = True
                    result['suspicious_chars'].append(f"{lookalike} (mimics {normal_char})")
        
        # Try to find potential target domain
        if result['detected']:
            normalized_domain = self._normalize_homograph_domain(domain)
            for category, domains in self.legitimate_domains.items():
                for legit_domain in domains:
                    if self._calculate_similarity(normalized_domain, legit_domain) > 0.8:
                        result['potential_target'] = legit_domain
                        break
        
        return result
    
    def _detect_domain_spoofing(self, domain: str) -> Dict[str, Any]:
        """
        Detect domain spoofing attempts
        """
        result = {
            'detected': False,
            'target_domain': None,
            'similarity': 0,
            'score': 0
        }
        
        domain_lower = domain.lower()
        
        # Check against all legitimate domains
        for category, domains in self.legitimate_domains.items():
            for legit_domain in domains:
                similarity = self._calculate_similarity(domain_lower, legit_domain)
                
                # High similarity but not exact match
                if 0.7 <= similarity < 1.0:
                    result['detected'] = True
                    result['target_domain'] = legit_domain
                    result['similarity'] = similarity
                    
                    # Score based on similarity and domain category
                    base_score = int((similarity - 0.7) * 100)
                    if category == 'financial':
                        result['score'] = base_score + 20  # Higher risk for financial spoofing
                    else:
                        result['score'] = base_score + 10
                    
                    return result
        
        return result
    
    def _analyze_subdomain_abuse(self, domain_info) -> Dict[str, Any]:
        """
        Analyze subdomain patterns for abuse indicators
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'subdomains': domain_info.subdomain or ''
        }
        
        if not domain_info.subdomain:
            return result
        
        subdomain_parts = domain_info.subdomain.split('.')
        subdomain_count = len(subdomain_parts)
        
        # Rule: Excessive subdomain levels
        if subdomain_count > 4:
            result['suspicious'] = True
            result['score'] = 20
            result['severity'] = 'high'
            result['description'] = f'Excessive subdomain levels ({subdomain_count}) may indicate abuse'
        elif subdomain_count > 2:
            result['suspicious'] = True
            result['score'] = 10
            result['severity'] = 'medium'
            result['description'] = f'Multiple subdomain levels ({subdomain_count}) detected'
        
        # Rule: Suspicious subdomain patterns
        suspicious_patterns = ['www-', 'secure-', 'login-', 'account-', 'verify-']
        for pattern in suspicious_patterns:
            if any(pattern in part for part in subdomain_parts):
                result['suspicious'] = True
                result['score'] += 15
                result['severity'] = 'high'
                result['description'] += f' Contains suspicious pattern: {pattern}'
        
        return result
    
    def _analyze_suspicious_characters(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain for suspicious character patterns
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'patterns': []
        }
        
        # Check for excessive hyphens
        hyphen_count = domain.count('-')
        if hyphen_count > 3:
            result['suspicious'] = True
            result['score'] += 10
            result['patterns'].append(f'{hyphen_count} hyphens')
        
        # Check for number-letter mixing (potential typosquatting)
        if re.search(r'[0-9][a-zA-Z]|[a-zA-Z][0-9]', domain):
            result['suspicious'] = True
            result['score'] += 8
            result['patterns'].append('number-letter mixing')
        
        # Check for repeated characters
        repeated_chars = re.findall(r'(.)\1{2,}', domain)
        if repeated_chars:
            result['suspicious'] = True
            result['score'] += 5
            result['patterns'].append(f'repeated characters: {", ".join(set(repeated_chars))}')
        
        if result['suspicious']:
            if result['score'] >= 15:
                result['severity'] = 'high'
            elif result['score'] >= 8:
                result['severity'] = 'medium'
            
            result['description'] = f'Suspicious character patterns detected: {", ".join(result["patterns"])}'
        
        return result
    
    def _normalize_homograph_domain(self, domain: str) -> str:
        """
        Normalize domain by replacing lookalike characters
        """
        normalized = domain.lower()
        for normal_char, lookalikes in self.homograph_chars.items():
            for lookalike in lookalikes:
                normalized = normalized.replace(lookalike, normal_char)
        return normalized
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """
        Calculate similarity between two strings using SequenceMatcher
        """
        return SequenceMatcher(None, str1, str2).ratio()

    def analyze_url_structure_rules(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive URL structure analysis
        """
        results = {
            'risk_score': 0,
            'rules_triggered': [],
            'url_analysis': {},
            'suspicious_patterns': []
        }
        
        try:
            parsed_url = urlparse(url)
            
            # Rule 1: URL Length Analysis
            url_length_result = self._analyze_url_length(url)
            if url_length_result['suspicious']:
                results['risk_score'] += url_length_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'URL_LENGTH',
                    'rule_name': 'URL Length Analysis',
                    'severity': url_length_result['severity'],
                    'score': url_length_result['score'],
                    'description': url_length_result['description'],
                    'detected_value': f"{len(url)} characters"
                })
            
            # Rule 2: Path Analysis
            path_result = self._analyze_path_structure(parsed_url.path)
            if path_result['suspicious']:
                results['risk_score'] += path_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'PATH_ANALYSIS',
                    'rule_name': 'Suspicious Path Structure',
                    'severity': path_result['severity'],
                    'score': path_result['score'],
                    'description': path_result['description'],
                    'detected_value': path_result['suspicious_elements']
                })
            
            # Rule 3: Query Parameter Analysis
            query_result = self._analyze_query_parameters(parsed_url.query)
            if query_result['suspicious']:
                results['risk_score'] += query_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'QUERY_PARAMS',
                    'rule_name': 'Suspicious Query Parameters',
                    'severity': query_result['severity'],
                    'score': query_result['score'],
                    'description': query_result['description'],
                    'detected_value': query_result['suspicious_params']
                })
            
            # Rule 4: URL Shortener Detection
            shortener_result = self._detect_url_shortener(url)
            if shortener_result['detected']:
                results['risk_score'] += shortener_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'URL_SHORTENER',
                    'rule_name': 'URL Shortener Service',
                    'severity': 'medium',
                    'score': shortener_result['score'],
                    'description': 'URL uses shortening service which can hide destination',
                    'detected_value': shortener_result['service']
                })
            
            # Rule 5: Special Character Analysis
            special_char_result = self._analyze_special_characters(url)
            if special_char_result['suspicious']:
                results['risk_score'] += special_char_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'SPECIAL_CHARS',
                    'rule_name': 'Suspicious Special Characters',
                    'severity': special_char_result['severity'],
                    'score': special_char_result['score'],
                    'description': special_char_result['description'],
                    'detected_value': special_char_result['characters']
                })
            
            # Rule 6: Keyword Analysis
            keyword_result = self._analyze_suspicious_keywords(url)
            if keyword_result['detected']:
                results['risk_score'] += keyword_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'SUSPICIOUS_KEYWORDS',
                    'rule_name': 'Phishing Keywords',
                    'severity': keyword_result['severity'],
                    'score': keyword_result['score'],
                    'description': keyword_result['description'],
                    'detected_value': keyword_result['keywords']
                })
            
            # Rule 7: Redirect Chain Detection
            redirect_result = self._detect_redirect_patterns(url)
            if redirect_result['suspicious']:
                results['risk_score'] += redirect_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'REDIRECT_PATTERNS',
                    'rule_name': 'Suspicious Redirect Patterns',
                    'severity': redirect_result['severity'],
                    'score': redirect_result['score'],
                    'description': redirect_result['description'],
                    'detected_value': redirect_result['patterns']
                })
            
            results['url_analysis'] = {
                'url_length': len(url),
                'path_length': len(parsed_url.path),
                'query_length': len(parsed_url.query),
                'fragment_length': len(parsed_url.fragment or ''),
                'scheme': parsed_url.scheme,
                'port': parsed_url.port
            }
            
        except Exception as e:
            results['error'] = f"URL structure analysis error: {str(e)}"
        
        return results
    
    def _analyze_url_length(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL length for suspicious patterns
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': ''
        }
        
        url_length = len(url)
        
        if url_length > 200:
            result['suspicious'] = True
            result['score'] = 25
            result['severity'] = 'high'
            result['description'] = f'Extremely long URL ({url_length} chars) may indicate obfuscation'
        elif url_length > 100:
            result['suspicious'] = True
            result['score'] = 15
            result['severity'] = 'medium'
            result['description'] = f'Long URL ({url_length} chars) detected'
        elif url_length > 75:
            result['suspicious'] = True
            result['score'] = 8
            result['severity'] = 'low'
            result['description'] = f'Moderately long URL ({url_length} chars)'
        
        return result
    
    def _analyze_path_structure(self, path: str) -> Dict[str, Any]:
        """
        Analyze URL path for suspicious patterns
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'suspicious_elements': []
        }
        
        if not path or path == '/':
            return result
        
        # Check path depth
        path_parts = [p for p in path.split('/') if p]
        if len(path_parts) > 6:
            result['suspicious'] = True
            result['score'] += 10
            result['suspicious_elements'].append(f'Deep path ({len(path_parts)} levels)')
        
        # Check for suspicious path patterns
        suspicious_path_patterns = [
            r'/[a-zA-Z0-9]{20,}',  # Long random strings
            r'/\d{10,}',           # Long numeric sequences
            r'/[^/]*\.(php|asp|jsp)\?',  # Dynamic pages with parameters
            r'/wp-admin|/admin',   # Admin panels
            r'/cgi-bin',           # CGI scripts
        ]
        
        for pattern in suspicious_path_patterns:
            if re.search(pattern, path):
                result['suspicious'] = True
                result['score'] += 8
                result['suspicious_elements'].append(f'Pattern: {pattern}')
        
        # Check for encoded characters
        if '%' in path:
            encoded_count = path.count('%')
            if encoded_count > 3:
                result['suspicious'] = True
                result['score'] += 12
                result['suspicious_elements'].append(f'Excessive URL encoding ({encoded_count} encoded chars)')
        
        # Check for suspicious file extensions
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com']
        for ext in suspicious_extensions:
            if ext in path.lower():
                result['suspicious'] = True
                result['score'] += 20
                result['severity'] = 'high'
                result['suspicious_elements'].append(f'Suspicious file extension: {ext}')
        
        if result['suspicious']:
            if result['score'] >= 20:
                result['severity'] = 'high'
            elif result['score'] >= 10:
                result['severity'] = 'medium'
            
            result['description'] = f'Suspicious path elements: {", ".join(result["suspicious_elements"])}'
        
        return result
    
    def _analyze_query_parameters(self, query: str) -> Dict[str, Any]:
        """
        Analyze query parameters for suspicious patterns
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'suspicious_params': []
        }
        
        if not query:
            return result
        
        # Parse query parameters
        from urllib.parse import parse_qs
        try:
            params = parse_qs(query)
        except:
            return result
        
        # Check for excessive parameters
        if len(params) > 10:
            result['suspicious'] = True
            result['score'] += 10
            result['suspicious_params'].append(f'Excessive parameters ({len(params)})')
        
        # Check for suspicious parameter names
        suspicious_param_names = [
            'redirect', 'url', 'goto', 'next', 'return', 'continue',
            'exec', 'cmd', 'eval', 'system', 'shell',
            'username', 'password', 'login', 'auth'
        ]
        
        for param_name in params.keys():
            param_lower = param_name.lower()
            for suspicious in suspicious_param_names:
                if suspicious in param_lower:
                    result['suspicious'] = True
                    result['score'] += 8
                    result['suspicious_params'].append(f'Suspicious parameter: {param_name}')
        
        # Check for long parameter values
        for param_name, values in params.items():
            for value in values:
                if len(value) > 100:
                    result['suspicious'] = True
                    result['score'] += 5
                    result['suspicious_params'].append(f'Long parameter value: {param_name}')
        
        # Check for base64-like patterns
        for param_name, values in params.items():
            for value in values:
                if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', value):
                    result['suspicious'] = True
                    result['score'] += 12
                    result['suspicious_params'].append(f'Base64-like parameter: {param_name}')
        
        if result['suspicious']:
            if result['score'] >= 15:
                result['severity'] = 'high'
            elif result['score'] >= 8:
                result['severity'] = 'medium'
            
            result['description'] = f'Suspicious query parameters: {", ".join(result["suspicious_params"])}'
        
        return result
    
    def _detect_url_shortener(self, url: str) -> Dict[str, Any]:
        """
        Detect URL shortening services
        """
        result = {
            'detected': False,
            'service': None,
            'score': 15
        }
        
        url_lower = url.lower()
        for shortener in self.url_shorteners:
            if shortener in url_lower:
                result['detected'] = True
                result['service'] = shortener
                break
        
        return result
    
    def _analyze_special_characters(self, url: str) -> Dict[str, Any]:
        """
        Analyze special characters in URL
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'characters': []
        }
        
        # Count various special characters
        special_chars = {
            '@': url.count('@'),
            '%': url.count('%'),
            '&': url.count('&'),
            '=': url.count('='),
            '+': url.count('+'),
            '#': url.count('#'),
            '!': url.count('!'),
            '*': url.count('*'),
            '~': url.count('~')
        }
        
        total_special = sum(special_chars.values())
        
        # @ symbol in URL (potential redirect)
        if special_chars['@'] > 0:
            result['suspicious'] = True
            result['score'] += 15
            result['characters'].append(f"@ symbol ({special_chars['@']})")
        
        # Excessive URL encoding
        if special_chars['%'] > 5:
            result['suspicious'] = True
            result['score'] += 10
            result['characters'].append(f"Excessive encoding ({special_chars['%']} % chars)")
        
        # Too many special characters overall
        if total_special > 15:
            result['suspicious'] = True
            result['score'] += 8
            result['characters'].append(f'High special char count ({total_special})')
        
        if result['suspicious']:
            if result['score'] >= 15:
                result['severity'] = 'high'
            elif result['score'] >= 8:
                result['severity'] = 'medium'
            
            result['description'] = f'Suspicious special characters: {", ".join(result["characters"])}'
        
        return result
    
    def _analyze_suspicious_keywords(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL for suspicious keywords
        """
        result = {
            'detected': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'keywords': []
        }
        
        url_lower = url.lower()
        
        # Check each category of suspicious keywords
        for category, keywords in self.suspicious_keywords.items():
            for keyword in keywords:
                if keyword in url_lower:
                    result['detected'] = True
                    result['keywords'].append(f'{keyword} ({category})')
                    
                    # Different scores for different categories
                    if category == 'urgency':
                        result['score'] += 12
                    elif category == 'financial':
                        result['score'] += 15
                    elif category == 'security':
                        result['score'] += 10
                    elif category == 'rewards':
                        result['score'] += 8
        
        if result['detected']:
            if result['score'] >= 20:
                result['severity'] = 'high'
            elif result['score'] >= 10:
                result['severity'] = 'medium'
            
            result['description'] = f'Suspicious keywords detected: {", ".join(result["keywords"])}'
        
        return result
    
    def _detect_redirect_patterns(self, url: str) -> Dict[str, Any]:
        """
        Detect suspicious redirect patterns
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'patterns': []
        }
        
        # Check for double slashes in path (potential redirect)
        if '//' in url and not url.startswith('http://'):
            result['suspicious'] = True
            result['score'] += 12
            result['patterns'].append('Double slash redirect pattern')
        
        # Check for @ symbol (authentication bypass/redirect)
        if '@' in url:
            result['suspicious'] = True
            result['score'] += 18
            result['patterns'].append('@ symbol redirect pattern')
        
        # Check for multiple protocols
        protocol_count = url.count('http://') + url.count('https://')
        if protocol_count > 1:
            result['suspicious'] = True
            result['score'] += 20
            result['severity'] = 'high'
            result['patterns'].append('Multiple protocol patterns')
        
        if result['suspicious']:
            if result['score'] >= 18:
                result['severity'] = 'high'
            elif result['score'] >= 10:
                result['severity'] = 'medium'
            
            result['description'] = f'Suspicious redirect patterns: {", ".join(result["patterns"])}'
        
        return result

    def analyze_technical_indicators(self, url: str) -> Dict[str, Any]:
        """
        Analyze technical security indicators
        """
        results = {
            'risk_score': 0,
            'rules_triggered': [],
            'technical_analysis': {},
            'security_indicators': []
        }
        
        try:
            parsed_url = urlparse(url)
            
            # Rule 1: Protocol Security Analysis
            protocol_result = self._analyze_protocol_security(parsed_url)
            if protocol_result['suspicious']:
                results['risk_score'] += protocol_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'PROTOCOL_SECURITY',
                    'rule_name': 'Protocol Security Analysis',
                    'severity': protocol_result['severity'],
                    'score': protocol_result['score'],
                    'description': protocol_result['description'],
                    'detected_value': protocol_result['protocol_info']
                })
            
            # Rule 2: Port Analysis
            port_result = self._analyze_port_usage(parsed_url)
            if port_result['suspicious']:
                results['risk_score'] += port_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'PORT_ANALYSIS',
                    'rule_name': 'Suspicious Port Usage',
                    'severity': port_result['severity'],
                    'score': port_result['score'],
                    'description': port_result['description'],
                    'detected_value': port_result['port_info']
                })
            
            # Rule 3: IP Address Usage
            ip_result = self._analyze_ip_usage(parsed_url.hostname)
            if ip_result['detected']:
                results['risk_score'] += ip_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'IP_ADDRESS_USAGE',
                    'rule_name': 'Direct IP Address Usage',
                    'severity': ip_result['severity'],
                    'score': ip_result['score'],
                    'description': ip_result['description'],
                    'detected_value': ip_result['ip_info']
                })
            
            # Rule 4: SSL/TLS Certificate Analysis (for HTTPS URLs)
            if parsed_url.scheme == 'https':
                cert_result = self._analyze_ssl_certificate(url)
                if cert_result['suspicious']:
                    results['risk_score'] += cert_result['score']
                    results['rules_triggered'].append({
                        'rule_id': 'SSL_CERTIFICATE',
                        'rule_name': 'SSL Certificate Analysis',
                        'severity': cert_result['severity'],
                        'score': cert_result['score'],
                        'description': cert_result['description'],
                        'detected_value': cert_result['cert_info']
                    })
            
            # Rule 5: Domain Registration Analysis
            domain_reg_result = self._analyze_domain_registration(parsed_url.hostname)
            if domain_reg_result['suspicious']:
                results['risk_score'] += domain_reg_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'DOMAIN_REGISTRATION',
                    'rule_name': 'Domain Registration Analysis',
                    'severity': domain_reg_result['severity'],
                    'score': domain_reg_result['score'],
                    'description': domain_reg_result['description'],
                    'detected_value': domain_reg_result['reg_info']
                })
            
            # Rule 6: Redirect Chain Analysis
            redirect_chain_result = self._analyze_redirect_chain(url)
            if redirect_chain_result['suspicious']:
                results['risk_score'] += redirect_chain_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'REDIRECT_CHAIN',
                    'rule_name': 'Redirect Chain Analysis',
                    'severity': redirect_chain_result['severity'],
                    'score': redirect_chain_result['score'],
                    'description': redirect_chain_result['description'],
                    'detected_value': redirect_chain_result['chain_info']
                })
            
            results['technical_analysis'] = {
                'protocol': parsed_url.scheme,
                'port': parsed_url.port,
                'hostname': parsed_url.hostname,
                'uses_https': parsed_url.scheme == 'https',
                'uses_standard_port': self._is_standard_port(parsed_url)
            }
            
        except Exception as e:
            results['error'] = f"Technical analysis error: {str(e)}"
        
        return results
    
    def _analyze_protocol_security(self, parsed_url) -> Dict[str, Any]:
        """
        Analyze protocol security (HTTP vs HTTPS)
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'protocol_info': {}
        }
        
        scheme = parsed_url.scheme.lower()
        
        if scheme == 'http':
            result['suspicious'] = True
            result['score'] = 20
            result['severity'] = 'medium'
            result['description'] = 'Insecure HTTP protocol detected - data transmitted in plain text'
            result['protocol_info'] = {'protocol': 'HTTP', 'secure': False}
        elif scheme == 'ftp':
            result['suspicious'] = True
            result['score'] = 25
            result['severity'] = 'high'
            result['description'] = 'FTP protocol detected - highly insecure for web content'
            result['protocol_info'] = {'protocol': 'FTP', 'secure': False}
        elif scheme not in ['https', 'http', 'ftp']:
            result['suspicious'] = True
            result['score'] = 15
            result['severity'] = 'medium'
            result['description'] = f'Unusual protocol detected: {scheme}'
            result['protocol_info'] = {'protocol': scheme.upper(), 'secure': False}
        else:
            result['protocol_info'] = {'protocol': scheme.upper(), 'secure': scheme == 'https'}
        
        return result
    
    def _analyze_port_usage(self, parsed_url) -> Dict[str, Any]:
        """
        Analyze port usage for suspicious patterns
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'port_info': {}
        }
        
        port = parsed_url.port
        scheme = parsed_url.scheme.lower()
        
        if port is None:
            # Using default ports
            result['port_info'] = {'port': 'default', 'scheme': scheme}
            return result
        
        # Standard ports
        standard_ports = {
            'http': [80, 8080, 8000],
            'https': [443, 8443],
            'ftp': [21],
            'ssh': [22],
            'telnet': [23]
        }
        
        # Suspicious ports commonly used by malware/phishing
        suspicious_ports = [1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999]
        
        # High-numbered ports (often used to evade detection)
        if port > 49152:
            result['suspicious'] = True
            result['score'] = 12
            result['severity'] = 'medium'
            result['description'] = f'High-numbered port {port} detected - may indicate evasion attempt'
        
        # Suspicious ports
        elif port in suspicious_ports:
            result['suspicious'] = True
            result['score'] = 20
            result['severity'] = 'high'
            result['description'] = f'Suspicious port {port} commonly used by malware'
        
        # Non-standard ports for the protocol
        elif scheme in standard_ports and port not in standard_ports[scheme]:
            result['suspicious'] = True
            result['score'] = 8
            result['severity'] = 'low'
            result['description'] = f'Non-standard port {port} for {scheme.upper()} protocol'
        
        result['port_info'] = {'port': port, 'scheme': scheme, 'standard': not result['suspicious']}
        
        return result
    
    def _analyze_ip_usage(self, hostname: str) -> Dict[str, Any]:
        """
        Analyze direct IP address usage
        """
        result = {
            'detected': False,
            'score': 0,
            'severity': 'medium',
            'description': '',
            'ip_info': {}
        }
        
        if not hostname:
            return result
        
        import ipaddress
        
        try:
            # Check if hostname is an IP address
            ip = ipaddress.ip_address(hostname)
            result['detected'] = True
            result['score'] = 18
            
            if ip.is_private:
                result['score'] = 25
                result['severity'] = 'high'
                result['description'] = f'Private IP address {hostname} detected - likely internal/test server'
                result['ip_info'] = {'ip': hostname, 'type': 'private', 'version': ip.version}
            elif ip.is_loopback:
                result['score'] = 30
                result['severity'] = 'high'
                result['description'] = f'Loopback IP address {hostname} detected'
                result['ip_info'] = {'ip': hostname, 'type': 'loopback', 'version': ip.version}
            else:
                result['description'] = f'Direct IP address {hostname} usage instead of domain name'
                result['ip_info'] = {'ip': hostname, 'type': 'public', 'version': ip.version}
        
        except ValueError:
            # Not an IP address
            pass
        
        return result
    
    def _analyze_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """
        Analyze SSL certificate (basic check)
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'cert_info': {}
        }
        
        try:
            import ssl
            import socket
            from urllib.parse import urlparse
            
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        # Check certificate validity
                        import datetime
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        now = datetime.datetime.now()
                        
                        # Certificate expired or not yet valid
                        if now > not_after:
                            result['suspicious'] = True
                            result['score'] = 30
                            result['severity'] = 'high'
                            result['description'] = 'SSL certificate has expired'
                        elif now < not_before:
                            result['suspicious'] = True
                            result['score'] = 25
                            result['severity'] = 'high'
                            result['description'] = 'SSL certificate is not yet valid'
                        
                        # Certificate expires soon (within 30 days)
                        elif (not_after - now).days < 30:
                            result['suspicious'] = True
                            result['score'] = 10
                            result['severity'] = 'low'
                            result['description'] = f'SSL certificate expires soon ({(not_after - now).days} days)'
                        
                        # Check subject alternative names
                        san_list = []
                        if 'subjectAltName' in cert:
                            san_list = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                        
                        result['cert_info'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'not_after': cert['notAfter'],
                            'not_before': cert['notBefore'],
                            'san_list': san_list
                        }
        
        except Exception as e:
            result['suspicious'] = True
            result['score'] = 15
            result['severity'] = 'medium'
            result['description'] = f'SSL certificate analysis failed: {str(e)}'
            result['cert_info'] = {'error': str(e)}
        
        return result
    
    def _analyze_domain_registration(self, hostname: str) -> Dict[str, Any]:
        """
        Analyze domain registration information
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'reg_info': {}
        }
        
        if not hostname:
            return result
        
        try:
            import whois
            from datetime import datetime, timedelta
            
            domain_info = whois.whois(hostname)
            
            if domain_info:
                # Check domain age
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if creation_date:
                    domain_age = (datetime.now() - creation_date).days
                    
                    # Very new domains (less than 30 days)
                    if domain_age < 30:
                        result['suspicious'] = True
                        result['score'] = 20
                        result['severity'] = 'high'
                        result['description'] = f'Very new domain ({domain_age} days old)'
                    # New domains (less than 90 days)
                    elif domain_age < 90:
                        result['suspicious'] = True
                        result['score'] = 12
                        result['severity'] = 'medium'
                        result['description'] = f'New domain ({domain_age} days old)'
                
                # Check expiration date
                expiration_date = domain_info.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                
                if expiration_date:
                    days_to_expire = (expiration_date - datetime.now()).days
                    
                    # Domain expires soon
                    if days_to_expire < 30:
                        result['suspicious'] = True
                        result['score'] += 8
                        result['description'] += f' Domain expires in {days_to_expire} days'
                
                result['reg_info'] = {
                    'creation_date': str(creation_date) if creation_date else None,
                    'expiration_date': str(expiration_date) if expiration_date else None,
                    'registrar': domain_info.registrar,
                    'domain_age_days': domain_age if creation_date else None
                }
        
        except Exception as e:
            # WHOIS lookup failed - could be suspicious
            result['suspicious'] = True
            result['score'] = 5
            result['severity'] = 'low'
            result['description'] = f'Domain registration lookup failed: {str(e)}'
            result['reg_info'] = {'error': str(e)}
        
        return result
    
    def _analyze_redirect_chain(self, url: str) -> Dict[str, Any]:
        """
        Analyze redirect chains
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'chain_info': {}
        }
        
        try:
            import requests
            
            # Follow redirects and track the chain
            session = requests.Session()
            session.max_redirects = 10
            
            response = session.head(url, allow_redirects=True, timeout=5)
            
            # Check redirect history
            redirect_count = len(response.history)
            
            if redirect_count > 0:
                redirect_urls = [resp.url for resp in response.history] + [response.url]
                
                # Too many redirects
                if redirect_count > 3:
                    result['suspicious'] = True
                    result['score'] = 15
                    result['severity'] = 'medium'
                    result['description'] = f'Excessive redirects ({redirect_count} hops)'
                elif redirect_count > 1:
                    result['suspicious'] = True
                    result['score'] = 8
                    result['severity'] = 'low'
                    result['description'] = f'Multiple redirects ({redirect_count} hops)'
                
                # Check for protocol downgrade (HTTPS to HTTP)
                for i in range(len(redirect_urls) - 1):
                    current_url = urlparse(redirect_urls[i])
                    next_url = urlparse(redirect_urls[i + 1])
                    
                    if current_url.scheme == 'https' and next_url.scheme == 'http':
                        result['suspicious'] = True
                        result['score'] += 20
                        result['severity'] = 'high'
                        result['description'] += ' Protocol downgrade detected (HTTPS to HTTP)'
                
                result['chain_info'] = {
                    'redirect_count': redirect_count,
                    'redirect_urls': redirect_urls,
                    'final_url': response.url
                }
        
        except Exception as e:
            result['chain_info'] = {'error': str(e)}
        
        return result
    
    def _is_standard_port(self, parsed_url) -> bool:
        """
        Check if URL uses standard port for its protocol
        """
        scheme = parsed_url.scheme.lower()
        port = parsed_url.port
        
        standard_ports = {
            'http': 80,
            'https': 443,
            'ftp': 21
        }
        
        if port is None:
            return True  # Using default port
        
        return scheme in standard_ports and port == standard_ports[scheme]

    def analyze_content_rules(self, html_content: str, url: str = None) -> Dict[str, Any]:
        """
        Analyze HTML content for phishing indicators using industry-standard rules
        """
        rules_triggered = []
        total_score = 0.0
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Rule 1: Suspicious form analysis
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '').lower()
                method = form.get('method', 'get').lower()
                
                # Check for external form submission
                if action and ('http' in action or '//' in action):
                    if url:
                        parsed_url = urlparse(url)
                        parsed_action = urlparse(action)
                        if parsed_action.netloc and parsed_action.netloc != parsed_url.netloc:
                            rules_triggered.append({
                                'rule_id': 'CONTENT_001',
                                'category': 'content',
                                'severity': 'high',
                                'score': 35.0,
                                'description': 'Form submits to external domain',
                                'details': f'Form action: {action}'
                            })
                            total_score += 35.0
                
                # Check for password fields without HTTPS
                password_fields = form.find_all('input', {'type': 'password'})
                if password_fields and url and not url.startswith('https://'):
                    rules_triggered.append({
                        'rule_id': 'CONTENT_002',
                        'category': 'content',
                        'severity': 'high',
                        'score': 40.0,
                        'description': 'Password field on non-HTTPS page',
                        'details': 'Insecure password transmission'
                    })
                    total_score += 40.0
                
                # Check for suspicious input fields
                sensitive_fields = ['ssn', 'social', 'credit', 'card', 'cvv', 'pin']
                inputs = form.find_all('input')
                for inp in inputs:
                    name = inp.get('name', '').lower()
                    placeholder = inp.get('placeholder', '').lower()
                    for sensitive in sensitive_fields:
                        if sensitive in name or sensitive in placeholder:
                            rules_triggered.append({
                                'rule_id': 'CONTENT_003',
                                'category': 'content',
                                'severity': 'medium',
                                'score': 20.0,
                                'description': f'Requests sensitive information: {sensitive}',
                                'details': f'Field: {name or placeholder}'
                            })
                            total_score += 20.0
                            break
            
            # Rule 2: Brand impersonation detection
            brand_keywords = {
                'paypal': ['paypal', 'pay pal'],
                'amazon': ['amazon', 'amaz0n', 'amazom'],
                'google': ['google', 'g00gle', 'googIe'],
                'microsoft': ['microsoft', 'micr0soft', 'microsft'],
                'apple': ['apple', 'appIe', 'app1e'],
                'facebook': ['facebook', 'faceb00k', 'facebok'],
                'instagram': ['instagram', 'instagr4m', 'instgram'],
                'twitter': ['twitter', 'twiter', 'tw1tter'],
                'linkedin': ['linkedin', 'linkedln', 'link3din']
            }
            
            page_text = soup.get_text().lower()
            title_text = soup.find('title')
            title_text = title_text.string.lower() if title_text and title_text.string else ''
            
            for brand, variations in brand_keywords.items():
                for variation in variations:
                    if variation in page_text or variation in title_text:
                        # Check if it's legitimate brand context
                        if url and not self._is_legitimate_brand_domain(url, brand):
                            rules_triggered.append({
                                'rule_id': 'CONTENT_004',
                                'category': 'content',
                                'severity': 'high',
                                'score': 45.0,
                                'description': f'Brand impersonation detected: {brand}',
                                'details': f'Found "{variation}" on non-{brand} domain'
                            })
                            total_score += 45.0
                        break
            
            # Rule 3: Suspicious script analysis
            scripts = soup.find_all('script')
            for script in scripts:
                src = script.get('src', '')
                if src:
                    # External scripts from suspicious domains
                    parsed_src = urlparse(src)
                    if parsed_src.netloc and self._is_suspicious_script_domain(parsed_src.netloc):
                        rules_triggered.append({
                            'rule_id': 'CONTENT_005',
                            'category': 'content',
                            'severity': 'medium',
                            'score': 25.0,
                            'description': 'Suspicious external script',
                            'details': f'Script source: {src}'
                        })
                        total_score += 25.0
                
                # Inline script analysis
                if script.string:
                    script_content = script.string.lower()
                    suspicious_patterns = [
                        'eval(', 'document.write(', 'fromcharcode(',
                        'unescape(', 'atob(', 'btoa(',
                        'location.href', 'window.location'
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in script_content:
                            rules_triggered.append({
                                'rule_id': 'CONTENT_006',
                                'category': 'content',
                                'severity': 'medium',
                                'score': 15.0,
                                'description': f'Suspicious script pattern: {pattern}',
                                'details': 'Potentially obfuscated or malicious code'
                            })
                            total_score += 15.0
                            break
            
            # Rule 4: Hidden element analysis
            hidden_elements = soup.find_all(['div', 'span', 'input'], {'style': re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden')})
            hidden_elements.extend(soup.find_all(['input'], {'type': 'hidden'}))
            
            if len(hidden_elements) > 10:
                rules_triggered.append({
                    'rule_id': 'CONTENT_007',
                    'category': 'content',
                    'severity': 'low',
                    'score': 10.0,
                    'description': 'Excessive hidden elements',
                    'details': f'{len(hidden_elements)} hidden elements found'
                })
                total_score += 10.0
            
            # Rule 5: Iframe analysis
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                src = iframe.get('src', '')
                if src:
                    parsed_src = urlparse(src)
                    if parsed_src.netloc and url:
                        parsed_url = urlparse(url)
                        if parsed_src.netloc != parsed_url.netloc:
                            rules_triggered.append({
                                'rule_id': 'CONTENT_008',
                                'category': 'content',
                                'severity': 'medium',
                                'score': 20.0,
                                'description': 'External iframe detected',
                                'details': f'Iframe source: {src}'
                            })
                            total_score += 20.0
            
            # Rule 6: Urgency and social engineering keywords
            urgency_keywords = [
                'urgent', 'immediate', 'expires today', 'act now',
                'limited time', 'verify now', 'suspend', 'suspended',
                'click here', 'update payment', 'confirm identity',
                'security alert', 'account locked', 'unusual activity'
            ]
            
            for keyword in urgency_keywords:
                if keyword in page_text:
                    rules_triggered.append({
                        'rule_id': 'CONTENT_009',
                        'category': 'content',
                        'severity': 'medium',
                        'score': 12.0,
                        'description': f'Social engineering keyword: {keyword}',
                        'details': 'Uses urgency or fear tactics'
                    })
                    total_score += 12.0
                    break
            
            # Rule 7: Suspicious link analysis
            links = soup.find_all('a', href=True)
            external_links = 0
            suspicious_links = 0
            
            for link in links:
                href = link.get('href', '')
                if href.startswith('http'):
                    external_links += 1
                    parsed_href = urlparse(href)
                    if url:
                        parsed_url = urlparse(url)
                        if parsed_href.netloc != parsed_url.netloc:
                            # Check for URL shorteners or suspicious domains
                            if self._is_url_shortener_domain(parsed_href.netloc) or self._is_suspicious_domain(parsed_href.netloc):
                                suspicious_links += 1
            
            if external_links > 0 and (suspicious_links / external_links) > 0.3:
                rules_triggered.append({
                    'rule_id': 'CONTENT_010',
                    'category': 'content',
                    'severity': 'medium',
                    'score': 18.0,
                    'description': 'High ratio of suspicious external links',
                    'details': f'{suspicious_links}/{external_links} suspicious links'
                })
                total_score += 18.0
        
        except Exception as e:
            rules_triggered.append({
                'rule_id': 'CONTENT_ERROR',
                'category': 'content',
                'severity': 'low',
                'score': 0.0,
                'description': 'Content analysis error',
                'details': str(e)
            })
        
        return {
            'rules_triggered': rules_triggered,
            'total_score': min(total_score, 100.0),
            'rule_count': len(rules_triggered),
            'category': 'content'
        }
    
    def _is_legitimate_brand_domain(self, url: str, brand: str) -> bool:
        """
        Check if URL is from legitimate brand domain
        """
        legitimate_domains = {
            'paypal': ['paypal.com', 'paypal.me'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amzn.to'],
            'google': ['google.com', 'gmail.com', 'youtube.com', 'goo.gl'],
            'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'msn.com'],
            'apple': ['apple.com', 'icloud.com', 'me.com'],
            'facebook': ['facebook.com', 'fb.com', 'messenger.com'],
            'instagram': ['instagram.com'],
            'twitter': ['twitter.com', 't.co'],
            'linkedin': ['linkedin.com']
        }
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        brand_domains = legitimate_domains.get(brand, [])
        for legitimate_domain in brand_domains:
            if domain == legitimate_domain or domain.endswith('.' + legitimate_domain):
                return True
        
        return False
    
    def _is_suspicious_script_domain(self, domain: str) -> bool:
        """
        Check if script domain is suspicious
        """
        suspicious_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IP addresses
            r'[a-z0-9]{10,}\.com',    # Random long domains
            r'.*\.tk$', r'.*\.ml$', r'.*\.ga$'  # Suspicious TLDs
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, domain.lower()):
                return True
        
        return False
    
    def _is_url_shortener_domain(self, domain: str) -> bool:
        """
        Check if domain is a URL shortener
        """
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
            'ow.ly', 'buff.ly', 'is.gd', 'tiny.cc', 'rebrand.ly'
        ]
        return domain.lower() in shorteners
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """
        Check if domain appears suspicious
        """
        # Check for IP addresses
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            return True
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return True
        
        # Check for excessive subdomains
        if domain.count('.') > 3:
            return True
        
        return False

    def comprehensive_rule_analysis(self, url: str, html_content: str = None) -> Dict[str, Any]:
        """
        Comprehensive analysis using all rule categories with weighted scoring
        """
        results = {
            'overall_risk_score': 0,
            'risk_level': 'low',
            'confidence': 0.0,
            'all_rules_triggered': [],
            'category_scores': {},
            'analysis_summary': {},
            'recommendations': []
        }
        
        try:
            # Category weights (total = 1.0)
            category_weights = {
                'domain': 0.30,      # Domain-based rules
                'structure': 0.25,   # URL structure rules
                'technical': 0.35,   # Technical indicators
                'content': 0.10      # Content-based rules (placeholder)
            }
            
            # Run all rule categories
            domain_results = self.analyze_domain_rules(url)
            structure_results = self.analyze_url_structure_rules(url)
            technical_results = self.analyze_technical_indicators(url)
            
            # Run content analysis if HTML content is provided
            content_results = None
            content_weighted = 0.0
            if html_content:
                content_results = self.analyze_content_rules(html_content, url)
                content_weighted = content_results['total_score'] * category_weights['content']
            
            # Calculate weighted scores
            domain_weighted = domain_results['risk_score'] * category_weights['domain']
            structure_weighted = structure_results['risk_score'] * category_weights['structure']
            technical_weighted = technical_results['risk_score'] * category_weights['technical']
            
            # Combine all triggered rules
            all_rules = []
            all_rules.extend(domain_results.get('rules_triggered', []))
            all_rules.extend(structure_results.get('rules_triggered', []))
            all_rules.extend(technical_results.get('rules_triggered', []))
            if content_results:
                all_rules.extend(content_results.get('rules_triggered', []))
            
            # Calculate overall risk score
            raw_score = domain_weighted + structure_weighted + technical_weighted + content_weighted
            
            # Apply rule interaction bonuses/penalties
            interaction_bonus = self._calculate_rule_interactions(all_rules)
            
            # Final score with normalization (0-100 scale)
            final_score = min(100, raw_score + interaction_bonus)
            
            # Determine risk level and confidence
            risk_level, confidence = self._determine_risk_level(final_score, len(all_rules))
            
            # Generate recommendations
            recommendations = self._generate_recommendations(all_rules, risk_level)
            
            results.update({
                'overall_risk_score': round(final_score, 2),
                'risk_level': risk_level,
                'confidence': round(confidence, 2),
                'all_rules_triggered': all_rules,
                'category_scores': {
                    'domain': {
                        'raw_score': domain_results['risk_score'],
                        'weighted_score': round(domain_weighted, 2),
                        'rules_count': len(domain_results.get('rules_triggered', []))
                    },
                    'structure': {
                        'raw_score': structure_results['risk_score'],
                        'weighted_score': round(structure_weighted, 2),
                        'rules_count': len(structure_results.get('rules_triggered', []))
                    },
                    'technical': {
                        'raw_score': technical_results['risk_score'],
                        'weighted_score': round(technical_weighted, 2),
                        'rules_count': len(technical_results.get('rules_triggered', []))
                    },
                    'content': {
                        'raw_score': content_results['total_score'] if content_results else 0.0,
                        'weighted_score': round(content_weighted, 2),
                        'rules_count': len(content_results.get('rules_triggered', [])) if content_results else 0
                    }
                },
                'analysis_summary': {
                    'total_rules_triggered': len(all_rules),
                    'high_severity_rules': len([r for r in all_rules if r.get('severity') == 'high']),
                    'medium_severity_rules': len([r for r in all_rules if r.get('severity') == 'medium']),
                    'low_severity_rules': len([r for r in all_rules if r.get('severity') == 'low']),
                    'interaction_bonus': round(interaction_bonus, 2)
                },
                'recommendations': recommendations,
                'detailed_results': {
                    'domain_analysis': domain_results,
                    'structure_analysis': structure_results,
                    'technical_analysis': technical_results,
                    'content_analysis': content_results if content_results else {'rules_triggered': [], 'total_score': 0.0, 'rule_count': 0, 'category': 'content'}
                }
            })
            
        except Exception as e:
            results['error'] = f"Comprehensive analysis error: {str(e)}"
        
        return results
    
    def _calculate_rule_interactions(self, rules: List[Dict]) -> float:
        """
        Calculate bonus/penalty based on rule interactions
        """
        if not rules:
            return 0
        
        interaction_bonus = 0
        rule_ids = [rule.get('rule_id', '') for rule in rules]
        
        # High-risk combinations
        high_risk_combinations = [
            ['IP_ADDRESS_USAGE', 'PROTOCOL_SECURITY'],  # IP + HTTP
            ['HOMOGRAPH_ATTACK', 'DOMAIN_SPOOFING'],     # Homograph + spoofing
            ['URL_SHORTENER', 'REDIRECT_PATTERNS'],      # Shortener + redirects
            ['SUSPICIOUS_KEYWORDS', 'NEW_DOMAIN'],       # Keywords + new domain
            ['SSL_CERTIFICATE', 'DOMAIN_REGISTRATION']   # Bad cert + suspicious domain
        ]
        
        for combination in high_risk_combinations:
            if all(rule_id in rule_ids for rule_id in combination):
                interaction_bonus += 15  # Significant bonus for dangerous combinations
        
        # Multiple high-severity rules bonus
        high_severity_count = len([r for r in rules if r.get('severity') == 'high'])
        if high_severity_count >= 3:
            interaction_bonus += 10
        elif high_severity_count >= 2:
            interaction_bonus += 5
        
        # Diminishing returns for too many low-severity rules
        low_severity_count = len([r for r in rules if r.get('severity') == 'low'])
        if low_severity_count > 5:
            interaction_bonus -= 5  # Penalty for noise
        
        return interaction_bonus
    
    def _determine_risk_level(self, score: float, rule_count: int) -> tuple:
        """
        Determine risk level and confidence based on score and rule count
        """
        # Base confidence on number of rules triggered
        base_confidence = min(0.9, 0.3 + (rule_count * 0.1))
        
        if score >= 75:
            return 'critical', min(0.95, base_confidence + 0.2)
        elif score >= 60:
            return 'high', min(0.9, base_confidence + 0.15)
        elif score >= 40:
            return 'medium', min(0.8, base_confidence + 0.1)
        elif score >= 20:
            return 'low', min(0.7, base_confidence)
        else:
            return 'minimal', min(0.6, base_confidence - 0.1)
    
    def _generate_recommendations(self, rules: List[Dict], risk_level: str) -> List[str]:
        """
        Generate security recommendations based on triggered rules
        """
        recommendations = []
        rule_ids = [rule.get('rule_id', '') for rule in rules]
        
        # Protocol-specific recommendations
        if 'PROTOCOL_SECURITY' in rule_ids:
            recommendations.append("Verify the website uses HTTPS encryption")
        
        # Domain-specific recommendations
        if 'DOMAIN_SPOOFING' in rule_ids:
            recommendations.append("Check the domain name carefully for typos or character substitutions")
        
        if 'HOMOGRAPH_ATTACK' in rule_ids:
            recommendations.append("Be cautious of domains using similar-looking characters from different alphabets")
        
        # Technical recommendations
        if 'IP_ADDRESS_USAGE' in rule_ids:
            recommendations.append("Avoid clicking links that use IP addresses instead of domain names")
        
        if 'SSL_CERTIFICATE' in rule_ids:
            recommendations.append("Check the SSL certificate validity and issuer")
        
        # URL structure recommendations
        if 'URL_SHORTENER' in rule_ids:
            recommendations.append("Be cautious with shortened URLs - expand them to see the destination")
        
        if 'SUSPICIOUS_KEYWORDS' in rule_ids:
            recommendations.append("Be wary of urgent language or offers that seem too good to be true")
        
        # General recommendations based on risk level
        if risk_level in ['critical', 'high']:
            recommendations.extend([
                "Do not enter personal information on this website",
                "Do not download files from this source",
                "Consider reporting this URL to security authorities"
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                "Exercise caution when interacting with this website",
                "Verify the website's legitimacy through official channels"
            ])
        
        return recommendations
    
    def get_rule_weights(self) -> Dict[str, float]:
        """
        Get current rule category weights
        """
        return {
            'domain': 0.30,
            'structure': 0.25,
            'technical': 0.35,
            'content': 0.10
        }
    
    def update_rule_weights(self, new_weights: Dict[str, float]) -> bool:
        """
        Update rule category weights (must sum to 1.0)
        """
        if abs(sum(new_weights.values()) - 1.0) > 0.01:
            return False
        
        self._rule_weights = new_weights
        return True
    
    def analyze_email_rules(self, email_content: str, email_headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Comprehensive email analysis using industry-standard phishing detection rules
        """
        results = {
            'risk_score': 0,
            'rules_triggered': [],
            'email_analysis': {},
            'sender_analysis': {},
            'content_analysis': {},
            'header_analysis': {}
        }
        
        try:
            email_lower = email_content.lower()
            
            # Rule 1: Sender Analysis
            sender_result = self._analyze_email_sender(email_content, email_headers)
            if sender_result['suspicious']:
                results['risk_score'] += sender_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'EMAIL_SENDER',
                    'rule_name': 'Suspicious Sender Analysis',
                    'severity': sender_result['severity'],
                    'score': sender_result['score'],
                    'description': sender_result['description'],
                    'detected_value': sender_result['details']
                })
            results['sender_analysis'] = sender_result
            
            # Rule 2: Header Analysis
            header_result = self._analyze_email_headers(email_headers or {})
            if header_result['suspicious']:
                results['risk_score'] += header_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'EMAIL_HEADERS',
                    'rule_name': 'Suspicious Email Headers',
                    'severity': header_result['severity'],
                    'score': header_result['score'],
                    'description': header_result['description'],
                    'detected_value': header_result['details']
                })
            results['header_analysis'] = header_result
            
            # Rule 3: Content Pattern Analysis
            content_result = self._analyze_email_content_patterns(email_content)
            if content_result['suspicious']:
                results['risk_score'] += content_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'EMAIL_CONTENT',
                    'rule_name': 'Suspicious Content Patterns',
                    'severity': content_result['severity'],
                    'score': content_result['score'],
                    'description': content_result['description'],
                    'detected_value': content_result['details']
                })
            results['content_analysis'] = content_result
            
            # Rule 4: BEC (Business Email Compromise) Detection
            bec_result = self._analyze_bec_indicators(email_content, email_headers)
            if bec_result['suspicious']:
                results['risk_score'] += bec_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'EMAIL_BEC',
                    'rule_name': 'Business Email Compromise Indicators',
                    'severity': bec_result['severity'],
                    'score': bec_result['score'],
                    'description': bec_result['description'],
                    'detected_value': bec_result['details']
                })
            
            # Rule 5: URL Analysis in Email
            url_result = self._analyze_email_urls(email_content)
            if url_result['suspicious']:
                results['risk_score'] += url_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'EMAIL_URLS',
                    'rule_name': 'Suspicious URLs in Email',
                    'severity': url_result['severity'],
                    'score': url_result['score'],
                    'description': url_result['description'],
                    'detected_value': url_result['details']
                })
            
            # Rule 6: Attachment Analysis
            attachment_result = self._analyze_email_attachments(email_content)
            if attachment_result['suspicious']:
                results['risk_score'] += attachment_result['score']
                results['rules_triggered'].append({
                    'rule_id': 'EMAIL_ATTACHMENTS',
                    'rule_name': 'Suspicious Email Attachments',
                    'severity': attachment_result['severity'],
                    'score': attachment_result['score'],
                    'description': attachment_result['description'],
                    'detected_value': attachment_result['details']
                })
            
            results['email_analysis'] = {
                'email_length': len(email_content),
                'num_urls': len(re.findall(r'https?://[^\s<>"\'\']+', email_content)),
                'has_html': '<html' in email_lower or '<body' in email_lower,
                'urgency_indicators': len([phrase for phrase in self.email_urgent_phrases if phrase in email_lower]),
                'personal_info_requests': len([req for req in self.email_personal_info_requests if req in email_lower])
            }
            
        except Exception as e:
            results['error'] = f"Email analysis error: {str(e)}"
        
        return results
    
    def _analyze_email_sender(self, email_content: str, email_headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Analyze email sender for suspicious indicators
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'details': []
        }
        
        try:
            # Extract sender information
            from_match = re.search(r'From:\s*([^<\n]+)', email_content, re.IGNORECASE)
            email_match = re.search(r'From:.*?([^@\s]+@[^>\s]+)', email_content, re.IGNORECASE)
            
            if from_match:
                from_field = from_match.group(1).strip()
                
                # Check for executive impersonation
                if any(title in from_field.lower() for title in self.email_executive_titles):
                    result['suspicious'] = True
                    result['score'] += 15
                    result['severity'] = 'medium'
                    result['description'] = 'Sender claims executive title - common in BEC attacks'
                    result['details'].append(f'Executive title in sender: {from_field}')
                
                # Check for generic display names
                generic_names = ['admin', 'support', 'security', 'noreply', 'no-reply']
                if any(name in from_field.lower() for name in generic_names):
                    result['score'] += 10
                    result['details'].append(f'Generic sender name: {from_field}')
            
            if email_match:
                email_addr = email_match.group(1)
                
                # Check for domain spoofing
                if '@' in email_addr:
                    domain = email_addr.split('@')[1]
                    
                    # Check against legitimate domains for similarity
                    for category, domains in self.legitimate_domains.items():
                        for legit_domain in domains:
                            similarity = self._calculate_similarity(domain, legit_domain)
                            if 0.7 <= similarity < 0.95:  # Similar but not exact
                                result['suspicious'] = True
                                result['score'] += 25
                                result['severity'] = 'high'
                                result['description'] = 'Domain spoofing detected - similar to legitimate domain'
                                result['details'].append(f'Spoofed domain: {domain} (similar to {legit_domain})')
                
                # Check for suspicious TLDs
                domain_parts = email_addr.split('@')[1] if '@' in email_addr else ''
                if any(domain_parts.endswith(tld) for tld in self.suspicious_tlds):
                    result['suspicious'] = True
                    result['score'] += 15
                    result['severity'] = 'medium'
                    result['description'] = 'Sender uses suspicious top-level domain'
                    result['details'].append(f'Suspicious TLD in sender domain: {domain_parts}')
            
            # Check for reply-to mismatch
            reply_to_match = re.search(r'Reply-To:\s*[^@]+@([^\s>]+)', email_content, re.IGNORECASE)
            if reply_to_match and email_match:
                reply_domain = reply_to_match.group(1)
                from_domain = email_match.group(1).split('@')[1] if '@' in email_match.group(1) else ''
                
                if reply_domain != from_domain:
                    result['suspicious'] = True
                    result['score'] += 20
                    result['severity'] = 'high'
                    result['description'] = 'Reply-To domain differs from sender domain'
                    result['details'].append(f'Domain mismatch: From={from_domain}, Reply-To={reply_domain}')
        
        except Exception as e:
            result['error'] = f"Sender analysis error: {str(e)}"
        
        return result
    
    def _analyze_email_headers(self, email_headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze email headers for suspicious indicators
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'details': []
        }
        
        try:
            # Check for missing standard headers
            required_headers = ['from', 'to', 'subject', 'date']
            missing_headers = [h for h in required_headers if h.lower() not in [k.lower() for k in email_headers.keys()]]
            
            if missing_headers:
                result['suspicious'] = True
                result['score'] += len(missing_headers) * 5
                result['severity'] = 'medium'
                result['description'] = 'Missing standard email headers'
                result['details'].append(f'Missing headers: {", ".join(missing_headers)}')
            
            # Check for suspicious received headers
            received_headers = [v for k, v in email_headers.items() if k.lower() == 'received']
            if len(received_headers) < 2:
                result['score'] += 10
                result['details'].append('Insufficient received headers - possible direct send')
            
            # Check for suspicious authentication results
            auth_headers = ['authentication-results', 'dkim-signature', 'spf']
            auth_present = any(h.lower() in [k.lower() for k in email_headers.keys()] for h in auth_headers)
            
            if not auth_present:
                result['suspicious'] = True
                result['score'] += 15
                result['severity'] = 'medium'
                result['description'] = 'Missing email authentication headers'
                result['details'].append('No DKIM, SPF, or authentication results found')
        
        except Exception as e:
            result['error'] = f"Header analysis error: {str(e)}"
        
        return result
    
    def _analyze_email_content_patterns(self, email_content: str) -> Dict[str, Any]:
        """
        Analyze email content for suspicious patterns
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'details': []
        }
        
        try:
            content_lower = email_content.lower()
            
            # Check for urgent language
            urgent_count = sum(1 for phrase in self.email_urgent_phrases if phrase in content_lower)
            if urgent_count > 0:
                result['suspicious'] = True
                result['score'] += urgent_count * 10
                result['severity'] = 'medium' if urgent_count <= 2 else 'high'
                result['description'] = f'Contains {urgent_count} urgent language patterns'
                result['details'].append(f'Urgent phrases detected: {urgent_count}')
            
            # Check for generic greetings
            generic_greeting_count = sum(1 for greeting in self.email_generic_greetings if greeting in content_lower)
            if generic_greeting_count > 0:
                result['score'] += generic_greeting_count * 5
                result['details'].append(f'Generic greetings: {generic_greeting_count}')
            
            # Check for personal information requests
            personal_info_count = sum(1 for request in self.email_personal_info_requests if request in content_lower)
            if personal_info_count > 0:
                result['suspicious'] = True
                result['score'] += personal_info_count * 15
                result['severity'] = 'high'
                result['description'] = 'Requests personal/sensitive information'
                result['details'].append(f'Personal info requests: {personal_info_count}')
            
            # Check for spelling and grammar errors
            spelling_errors = self._count_spelling_errors(email_content)
            if spelling_errors > 3:
                result['score'] += min(spelling_errors * 2, 20)
                result['details'].append(f'Spelling/grammar errors: {spelling_errors}')
            
            # Check for suspicious links
            url_pattern = r'https?://[^\s<>"]+'
            urls = re.findall(url_pattern, email_content)
            if urls:
                suspicious_url_count = 0
                for url in urls:
                    if any(shortener in url for shortener in self.url_shorteners):
                        suspicious_url_count += 1
                
                if suspicious_url_count > 0:
                    result['suspicious'] = True
                    result['score'] += suspicious_url_count * 15
                    result['severity'] = 'high'
                    result['description'] = 'Contains suspicious shortened URLs'
                    result['details'].append(f'Suspicious URLs: {suspicious_url_count}/{len(urls)}')
        
        except Exception as e:
            result['error'] = f"Content analysis error: {str(e)}"
        
        return result
    
    def _analyze_bec_indicators(self, email_content: str) -> Dict[str, Any]:
        """
        Analyze for Business Email Compromise (BEC) indicators
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'details': []
        }
        
        try:
            content_lower = email_content.lower()
            
            # Check for BEC indicators
            bec_count = sum(1 for indicator in self.email_bec_indicators if indicator in content_lower)
            if bec_count > 0:
                result['suspicious'] = True
                result['score'] += bec_count * 20
                result['severity'] = 'high'
                result['description'] = 'Contains Business Email Compromise indicators'
                result['details'].append(f'BEC indicators detected: {bec_count}')
            
            # Check for executive impersonation in content
            executive_mentions = sum(1 for title in self.email_executive_titles if title in content_lower)
            if executive_mentions > 0:
                result['score'] += executive_mentions * 10
                result['details'].append(f'Executive title mentions: {executive_mentions}')
            
            # Check for financial requests
            financial_keywords = ['wire transfer', 'bank account', 'payment', 'invoice', 'urgent payment', 'financial']
            financial_count = sum(1 for keyword in financial_keywords if keyword in content_lower)
            if financial_count > 0:
                result['suspicious'] = True
                result['score'] += financial_count * 15
                result['severity'] = 'high'
                result['description'] = 'Contains financial transaction requests'
                result['details'].append(f'Financial keywords: {financial_count}')
        
        except Exception as e:
            result['error'] = f"BEC analysis error: {str(e)}"
        
        return result
    
    def _analyze_email_urls(self, email_content: str) -> Dict[str, Any]:
        """
        Analyze URLs within email content
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'details': []
        }
        
        try:
            # Extract URLs from email
            url_pattern = r'https?://[^\s<>"]+'
            urls = re.findall(url_pattern, email_content)
            
            if urls:
                total_url_score = 0
                suspicious_urls = 0
                
                for url in urls:
                    # Use existing URL analysis from comprehensive_rule_analysis
                    url_analysis = self.comprehensive_rule_analysis(url)
                    if url_analysis['risk_score'] > 30:
                        suspicious_urls += 1
                        total_url_score += url_analysis['risk_score']
                
                if suspicious_urls > 0:
                    result['suspicious'] = True
                    result['score'] = min(total_url_score // len(urls), 50)
                    result['severity'] = 'high' if result['score'] > 30 else 'medium'
                    result['description'] = f'Contains {suspicious_urls} suspicious URLs'
                    result['details'].append(f'Suspicious URLs: {suspicious_urls}/{len(urls)}')
                    result['details'].append(f'Average URL risk score: {total_url_score // len(urls) if urls else 0}')
        
        except Exception as e:
            result['error'] = f"URL analysis error: {str(e)}"
        
        return result
    
    def _analyze_email_attachments(self, email_content: str) -> Dict[str, Any]:
        """
        Analyze email attachments for suspicious indicators
        """
        result = {
            'suspicious': False,
            'score': 0,
            'severity': 'low',
            'description': '',
            'details': []
        }
        
        try:
            # Look for attachment indicators in email content
            attachment_patterns = [
                r'Content-Disposition:\s*attachment',
                r'filename\s*=\s*["\']?([^"\'>\s]+)',
                r'attachment[^\n]*\.(\w+)'
            ]
            
            attachments_found = []
            for pattern in attachment_patterns:
                matches = re.findall(pattern, email_content, re.IGNORECASE)
                attachments_found.extend(matches)
            
            if attachments_found:
                suspicious_attachments = 0
                
                for attachment in attachments_found:
                    # Check against suspicious attachment types
                    if any(ext in attachment.lower() for ext in self.email_suspicious_attachments):
                        suspicious_attachments += 1
                
                if suspicious_attachments > 0:
                    result['suspicious'] = True
                    result['score'] += suspicious_attachments * 25
                    result['severity'] = 'high'
                    result['description'] = 'Contains suspicious attachment types'
                    result['details'].append(f'Suspicious attachments: {suspicious_attachments}/{len(attachments_found)}')
                
                result['details'].append(f'Total attachments: {len(attachments_found)}')
        
        except Exception as e:
            result['error'] = f"Attachment analysis error: {str(e)}"
        
        return result
    
    def _count_spelling_errors(self, text: str) -> int:
        """
        Simple spelling error detection
        """
        try:
            # Basic patterns that indicate poor spelling/grammar
            error_patterns = [
                r'\b\w*[0-9]+\w*\b',  # Words with numbers mixed in
                r'\b[A-Z]{2,}\b',      # All caps words (excluding common abbreviations)
                r'[.!?]{2,}',          # Multiple punctuation
                r'\s{2,}',             # Multiple spaces
            ]
            
            error_count = 0
            for pattern in error_patterns:
                matches = re.findall(pattern, text)
                error_count += len(matches)
            
            return min(error_count, 10)  # Cap at 10
        except:
            return 0
    
    def _calculate_similarity(self, domain1: str, domain2: str) -> float:
        """
        Calculate similarity between two domains using simple character-based comparison
        """
        try:
            if not domain1 or not domain2:
                return 0.0
            
            # Simple Levenshtein-like similarity
            len1, len2 = len(domain1), len(domain2)
            if len1 == 0:
                return 0.0 if len2 > 0 else 1.0
            if len2 == 0:
                return 0.0
            
            # Create matrix for dynamic programming
            matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
            
            # Initialize first row and column
            for i in range(len1 + 1):
                matrix[i][0] = i
            for j in range(len2 + 1):
                matrix[0][j] = j
            
            # Fill the matrix
            for i in range(1, len1 + 1):
                for j in range(1, len2 + 1):
                    if domain1[i-1] == domain2[j-1]:
                        matrix[i][j] = matrix[i-1][j-1]
                    else:
                        matrix[i][j] = min(
                            matrix[i-1][j] + 1,    # deletion
                            matrix[i][j-1] + 1,    # insertion
                            matrix[i-1][j-1] + 1   # substitution
                        )
            
            # Calculate similarity as 1 - (distance / max_length)
            distance = matrix[len1][len2]
            max_length = max(len1, len2)
            similarity = 1.0 - (distance / max_length)
            
            return max(0.0, similarity)
        
        except Exception:
            return 0.0

# Global instance
rules_engine = IndustryStandardRulesEngine()

def analyze_domain_rules(url: str) -> Dict[str, Any]:
    """
    Analyze URL using industry-standard domain rules
    """
    return rules_engine.analyze_domain_rules(url)

def analyze_url_structure_rules(url: str) -> Dict[str, Any]:
    """
    Analyze URL using industry-standard structure rules
    """
    return rules_engine.analyze_url_structure_rules(url)

def analyze_technical_indicators(url: str) -> Dict[str, Any]:
    """
    Analyze URL using technical security indicators
    """
    return rules_engine.analyze_technical_indicators(url)

def analyze_content_rules(html_content: str, url: str = None) -> Dict[str, Any]:
    """
    Analyze HTML content using industry-standard content rules
    """
    return rules_engine.analyze_content_rules(html_content, url)

def analyze_email_rules(email_content: str, email_headers: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Analyze email using industry-standard email phishing rules
    """
    return rules_engine.analyze_email_rules(email_content, email_headers)

def comprehensive_rule_analysis(url: str, html_content: str = None) -> Dict[str, Any]:
    """
    Comprehensive analysis using all rule categories with weighted scoring
    """
    return rules_engine.comprehensive_rule_analysis(url, html_content)