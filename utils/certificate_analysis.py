
import ssl
import socket
import json
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64

class CertificateAnalyzer:
    def __init__(self):
        self.trusted_cas = self._load_trusted_cas()
    
    def _load_trusted_cas(self):
        """Load list of trusted Certificate Authorities"""
        # Common trusted CAs - in production, use a comprehensive list
        return [
            'DigiCert Inc',
            'Let\'s Encrypt',
            'GlobalSign',
            'VeriSign',
            'Symantec',
            'Comodo',
            'GeoTrust',
            'Thawte',
            'RapidSSL',
            'Sectigo'
        ]
    
    def analyze_domain_certificate(self, domain):
        """Analyze SSL certificate for a domain"""
        try:
            # Parse domain if URL is provided
            if domain.startswith(('http://', 'https://')):
                parsed = urlparse(domain)
                domain = parsed.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Get certificate
            cert_info = self._get_certificate_info(domain)
            if not cert_info:
                return self._create_error_result(domain, "Could not retrieve certificate")
            
            # Analyze certificate
            analysis = self._analyze_certificate(cert_info, domain)
            
            return {
                'domain': domain,
                'certificate_data': cert_info,
                'analysis': analysis,
                'result': analysis['overall_result'],
                'confidence': analysis['confidence'],
                'warnings': analysis['warnings'],
                'details': analysis['details']
            }
            
        except Exception as e:
            return self._create_error_result(domain, str(e))
    
    def _get_certificate_info(self, domain, port=443):
        """Get SSL certificate information for a domain"""
        try:
            # Get detailed SSL/TLS information using OpenSSL
            ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
            conn = OpenSSL.SSL.Connection(ssl_context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.connect((domain, port))
            conn.set_tlsext_host_name(domain.encode())
            conn.do_handshake()
            
            # Get TLS version and cipher information
            tls_version = conn.get_protocol_version_name()
            cipher = conn.get_cipher_name()
            cipher_bits = conn.get_cipher_bits()
            
            # Get certificate chain
            cert_chain = conn.get_peer_cert_chain()
            leaf_cert = conn.get_peer_certificate()
            
            conn.close()
            
            # Process leaf certificate
            subject = leaf_cert.get_subject()
            issuer = leaf_cert.get_issuer()
            
            # Format dates
            not_before = datetime.strptime(leaf_cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
            not_after = datetime.strptime(leaf_cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc)
            
            # Check if expired or self-signed
            now = datetime.now(timezone.utc)
            is_expired = not_after < now
            is_self_signed = subject.CN == issuer.CN if subject.CN and issuer.CN else False
            
            # Extract certificate information
            cert_info = {
                'hostname': domain,
                'tls_version': tls_version,
                'cipher': cipher,
                'cipher_bits': cipher_bits,
                'subject': self._format_openssl_name(subject),
                'issuer': self._format_openssl_name(issuer),
                'subject_cn': subject.CN,
                'issuer_cn': issuer.CN,
                'serial_number': str(leaf_cert.get_serial_number()),
                'version': leaf_cert.get_version() + 1,
                'not_valid_before': not_before.strftime('%Y-%m-%d %H:%M:%S'),
                'not_valid_after': not_after.strftime('%Y-%m-%d %H:%M:%S'),
                'signature_algorithm': leaf_cert.get_signature_algorithm().decode(),
                'public_key_size': leaf_cert.get_pubkey().bits(),
                'public_key_algorithm': 'RSA' if leaf_cert.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA else 'EC',
                'extensions': self._extract_openssl_extensions(leaf_cert),
                'is_expired': is_expired,
                'is_self_signed': is_self_signed,
                'certificate_chain': self._process_certificate_chain(cert_chain)
            }
            
            return cert_info
                    
        except Exception as e:
            print(f"OpenSSL method failed for {domain}: {str(e)}")
            # Fallback to original method if OpenSSL fails
            try:
                context = ssl.create_default_context()
                
                with socket.create_connection((domain, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        
                        # Extract certificate information
                        cert_info = {
                            'hostname': domain,
                            'tls_version': 'Unknown',
                            'cipher': 'Unknown',
                            'cipher_bits': 0,
                            'subject': self._format_name(cert.subject),
                            'issuer': self._format_name(cert.issuer),
                            'subject_cn': self._extract_cn_from_x509_name(cert.subject),
                            'issuer_cn': self._extract_cn_from_x509_name(cert.issuer),
                            'serial_number': str(cert.serial_number),
                            'version': cert.version.name,
                            'not_valid_before': cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S'),
                            'not_valid_after': cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
                            'signature_algorithm': cert.signature_algorithm_oid._name,
                            'public_key_size': cert.public_key().key_size,
                            'public_key_algorithm': cert.public_key().__class__.__name__,
                            'extensions': self._extract_extensions(cert),
                            'is_expired': cert.not_valid_after.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc),
                            'is_self_signed': self._format_name(cert.subject) == self._format_name(cert.issuer),
                            'certificate_chain': []
                        }
                        
                        return cert_info
                        
            except Exception as fallback_e:
                print(f"Fallback method also failed for {domain}: {str(fallback_e)}")
                return None
    
    def _format_name(self, name):
        """Format X.509 name to string"""
        return ', '.join([f"{attr.oid._name}={attr.value}" for attr in name])
    
    def _format_openssl_name(self, name):
        """Format OpenSSL X.509 name to string"""
        components = []
        for component in name.get_components():
            key = component[0].decode('utf-8')
            value = component[1].decode('utf-8')
            components.append(f"{key}={value}")
        return ', '.join(components)
    
    def _extract_cn_from_x509_name(self, name):
        """Extract Common Name from cryptography x509 name"""
        try:
            for attr in name:
                if attr.oid._name == 'commonName':
                    return attr.value
        except:
            pass
        return None
    
    def _process_certificate_chain(self, cert_chain):
        """Process certificate chain and return formatted details"""
        chain_details = []
        for i, cert in enumerate(cert_chain, start=1):
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            
            # Format dates
            not_before = datetime.strptime(cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
            not_after = datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
            
            chain_details.append({
                'certificate_number': i,
                'subject_cn': subject.CN,
                'issuer_cn': issuer.CN,
                'subject': self._format_openssl_name(subject),
                'issuer': self._format_openssl_name(issuer),
                'valid_from': not_before.strftime('%Y-%m-%d %H:%M:%S'),
                'valid_to': not_after.strftime('%Y-%m-%d %H:%M:%S'),
                'serial_number': str(cert.get_serial_number()),
                'version': cert.get_version() + 1,
                'public_key_size': cert.get_pubkey().bits(),
                'public_key_type': 'RSA' if cert.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA else 'EC'
            })
        
        return chain_details
    
    def _extract_openssl_extensions(self, cert):
        """Extract certificate extensions from OpenSSL certificate"""
        extensions = {}
        try:
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                ext_name = ext.get_short_name().decode()
                extensions[ext_name] = str(ext)
        except:
            pass
        return extensions
    
    def _extract_extensions(self, cert):
        """Extract certificate extensions"""
        extensions = {}
        try:
            for ext in cert.extensions:
                ext_name = ext.oid._name
                if ext_name == 'subjectAltName':
                    extensions[ext_name] = [name.value for name in ext.value]
                elif ext_name == 'keyUsage':
                    extensions[ext_name] = {
                        'digital_signature': ext.value.digital_signature,
                        'key_encipherment': ext.value.key_encipherment,
                        'data_encipherment': ext.value.data_encipherment,
                    }
                elif ext_name == 'extendedKeyUsage':
                    extensions[ext_name] = [usage._name for usage in ext.value]
                else:
                    extensions[ext_name] = str(ext.value)
        except:
            pass
        return extensions
    
    def _analyze_certificate(self, cert_info, domain):
        """Analyze certificate for security issues"""
        warnings = []
        details = []
        risk_score = 0
        
        # Check expiry
        try:
            not_after = datetime.strptime(cert_info['not_valid_after'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            not_before = datetime.strptime(cert_info['not_valid_before'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        except ValueError:
            # Fallback for different date formats
            not_after = datetime.fromisoformat(cert_info['not_valid_after'].replace('Z', '+00:00'))
            not_before = datetime.fromisoformat(cert_info['not_valid_before'].replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        
        days_until_expiry = (not_after - now).days
        
        if days_until_expiry < 0:
            warnings.append("Certificate has expired")
            risk_score += 50
            details.append("❌ Certificate expired")
        elif days_until_expiry < 30:
            warnings.append(f"Certificate expires in {days_until_expiry} days")
            risk_score += 20
            details.append(f"⚠️ Expires in {days_until_expiry} days")
        else:
            details.append(f"✅ Valid for {days_until_expiry} days")
        
        # Check if certificate is not yet valid
        if not_before > now:
            warnings.append("Certificate is not yet valid")
            risk_score += 30
            details.append("❌ Certificate not yet valid")
        
        # Check issuer
        issuer = cert_info['issuer']
        is_trusted_ca = any(ca in issuer for ca in self.trusted_cas)
        
        if not is_trusted_ca:
            warnings.append("Certificate issued by unknown CA")
            risk_score += 25
            details.append("⚠️ Unknown Certificate Authority")
        else:
            details.append("✅ Trusted Certificate Authority")
        
        # Check if self-signed
        if cert_info['subject'] == cert_info['issuer']:
            warnings.append("Self-signed certificate")
            risk_score += 40
            details.append("❌ Self-signed certificate")
        else:
            details.append("✅ Not self-signed")
        
        # Check key size
        key_size = cert_info['public_key_size']
        if key_size < 2048:
            warnings.append(f"Weak key size: {key_size} bits")
            risk_score += 30
            details.append(f"⚠️ Key size: {key_size} bits (weak)")
        else:
            details.append(f"✅ Key size: {key_size} bits")
        
        # Check signature algorithm
        sig_alg = cert_info['signature_algorithm']
        weak_algorithms = ['sha1', 'md5']
        if any(weak in sig_alg.lower() for weak in weak_algorithms):
            warnings.append(f"Weak signature algorithm: {sig_alg}")
            risk_score += 35
            details.append(f"⚠️ Signature: {sig_alg} (weak)")
        else:
            details.append(f"✅ Signature: {sig_alg}")
        
        # Check domain name matching
        subject_cn = self._extract_cn_from_subject(cert_info['subject'])
        san_names = cert_info['extensions'].get('subjectAltName', [])
        
        domain_matches = (subject_cn == domain or 
                         domain in san_names or 
                         any(self._wildcard_match(domain, san) for san in san_names))
        
        if not domain_matches:
            warnings.append("Certificate domain doesn't match requested domain")
            risk_score += 45
            details.append("❌ Domain mismatch")
        else:
            details.append("✅ Domain matches certificate")
        
        # Determine overall result
        if risk_score >= 50:
            overall_result = "invalid"
        elif risk_score >= 25:
            overall_result = "suspicious"
        else:
            overall_result = "trusted"
        
        confidence = max(0.1, 1.0 - (risk_score / 100))
        
        return {
            'overall_result': overall_result,
            'confidence': round(confidence, 2),
            'risk_score': risk_score,
            'warnings': warnings,
            'details': details,
            'expires_in_days': days_until_expiry,
            'is_expired': days_until_expiry < 0,
            'is_self_signed': cert_info['subject'] == cert_info['issuer'],
            'key_size': key_size,
            'signature_algorithm': sig_alg
        }
    
    def _extract_cn_from_subject(self, subject):
        """Extract Common Name from subject"""
        for part in subject.split(', '):
            if part.startswith('commonName='):
                return part.split('=', 1)[1]
        return None
    
    def _wildcard_match(self, domain, pattern):
        """Check if domain matches wildcard pattern"""
        if '*' not in pattern:
            return domain == pattern
        
        # Simple wildcard matching for *.example.com
        if pattern.startswith('*.'):
            pattern_domain = pattern[2:]
            return domain.endswith('.' + pattern_domain) or domain == pattern_domain
        
        return False
    
    def _create_error_result(self, domain, error_message):
        """Create error result structure"""
        return {
            'domain': domain,
            'error': error_message,
            'result': 'error',
            'confidence': 0.0,
            'warnings': [error_message],
            'details': ['❌ Analysis failed']
        }


# Global analyzer instance
analyzer = CertificateAnalyzer()

def analyze_certificate(domain):
    """Analyze certificate for a domain - wrapper function for routes"""
    result = analyzer.analyze_domain_certificate(domain)
    
    # Format detailed SSL/TLS information
    cert_data = result.get('certificate_data', {})
    analysis = result.get('analysis', {})
    
    # Create detailed formatted output
    detailed_info = []
    
    if cert_data:
        detailed_info.append("SSL/TLS Certificate Information:")
        detailed_info.append(f"Hostname: {cert_data.get('hostname', domain)}")
        detailed_info.append(f"TLS Version: {cert_data.get('tls_version', 'Unknown')}")
        detailed_info.append(f"Cipher: {cert_data.get('cipher', 'Unknown')}")
        detailed_info.append(f"Cipher Strength (bits): {cert_data.get('cipher_bits', 0)}")
        detailed_info.append(f"Leaf Certificate Subject: CN={cert_data.get('subject_cn', 'Unknown')}")
        detailed_info.append(f"Leaf Certificate Issuer: CN={cert_data.get('issuer_cn', 'Unknown')}")
        detailed_info.append(f"Valid From: {cert_data.get('not_valid_before', 'Unknown')}")
        detailed_info.append(f"Valid To: {cert_data.get('not_valid_after', 'Unknown')}")
        detailed_info.append(f"Expired: {cert_data.get('is_expired', True)}")
        detailed_info.append(f"Self-Signed: {cert_data.get('is_self_signed', False)}")
        
        # Add certificate chain details
        chain = cert_data.get('certificate_chain', [])
        if chain:
            detailed_info.append("")
            detailed_info.append("Certificate Chain Details:")
            for cert_detail in chain:
                detailed_info.append(f"  Certificate #{cert_detail.get('certificate_number', 1)}:")
                detailed_info.append(f"    Subject: CN={cert_detail.get('subject_cn', 'Unknown')}")
                detailed_info.append(f"    Issuer: CN={cert_detail.get('issuer_cn', 'Unknown')}")
                detailed_info.append(f"    Valid From: {cert_detail.get('valid_from', 'Unknown')}")
                detailed_info.append(f"    Valid To: {cert_detail.get('valid_to', 'Unknown')}")
    
    # Convert to format expected by routes
    return {
        'domain': result.get('domain', domain),
        'result': result.get('result', 'error'),
        'confidence': result.get('confidence', 0.0),
        'detection_methods': ['certificate_analysis'],
        'features': {
            'is_expired': cert_data.get('is_expired', True),
            'is_self_signed': cert_data.get('is_self_signed', False),
            'key_size': cert_data.get('public_key_size', 0),
            'signature_algorithm': cert_data.get('signature_algorithm', 'unknown'),
            'tls_version': cert_data.get('tls_version', 'Unknown'),
            'cipher': cert_data.get('cipher', 'Unknown'),
            'cipher_bits': cert_data.get('cipher_bits', 0)
        },
        'details': result.get('details', ['❌ Analysis failed']),
        'warnings': result.get('warnings', []),
        'certificate_info': cert_data,
        'analysis': analysis,
        'detailed_info': detailed_info
    }
