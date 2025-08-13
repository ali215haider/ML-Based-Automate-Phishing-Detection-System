
import csv
import os
import random
from datetime import datetime
from models import MLDataset, db

class DatasetManager:
    def __init__(self):
        self.dataset_path = 'data/datasets'
        os.makedirs(self.dataset_path, exist_ok=True)
    
    def generate_phishing_urls(self, count=3000):
        """Generate phishing URL dataset"""
        phishing_patterns = [
            'paypal-security-{}.com',
            'amazon-verify-{}.net', 
            'microsoft-login-{}.org',
            'google-secure-{}.info',
            'apple-id-{}.co',
            'banking-secure-{}.net',
            'facebook-security-{}.com',
            'twitter-verify-{}.org',
            'instagram-login-{}.info',
            'linkedin-update-{}.net'
        ]
        
        suspicious_words = ['verify', 'secure', 'update', 'confirm', 'urgent', 'suspended', 'limited', 'expired']
        
        urls = []
        for i in range(count):
            pattern = random.choice(phishing_patterns)
            random_id = random.randint(1000, 9999)
            url = pattern.format(random_id)
            
            # Add suspicious parameters
            if random.random() > 0.5:
                param = random.choice(suspicious_words)
                url += f'?{param}=true'
            
            urls.append({'content': f'http://{url}', 'label': 'phishing', 'source': 'generated'})
        
        return urls
    
    def generate_legitimate_urls(self, count=3000):
        """Generate legitimate URL dataset"""
        legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
            'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
            'youtube.com', 'netflix.com', 'spotify.com', 'dropbox.com', 'adobe.com',
            'salesforce.com', 'oracle.com', 'ibm.com', 'intel.com', 'cisco.com'
        ]
        
        paths = ['/', '/about', '/contact', '/products', '/services', '/help', '/support', '/blog', '/news']
        
        urls = []
        for i in range(count):
            domain = random.choice(legitimate_domains)
            path = random.choice(paths)
            protocol = random.choice(['https', 'http'])
            
            url = f'{protocol}://{domain}{path}'
            if random.random() > 0.7:
                url += f'?page={random.randint(1, 10)}'
            
            urls.append({'content': url, 'label': 'legitimate', 'source': 'generated'})
        
        return urls
    
    def generate_phishing_emails(self, count=2500):
        """Generate phishing email dataset"""
        templates = [
            "URGENT: Your account will be suspended unless you verify immediately. Click here: {}",
            "Security Alert: Suspicious activity detected. Confirm your identity: {}",
            "Your payment failed. Update your payment method: {}",
            "Limited time offer! Claim your prize now: {}",
            "IRS Notice: You owe taxes. Pay immediately to avoid penalties: {}",
            "Bank Alert: Your account has been compromised. Secure it now: {}"
        ]
        
        sender_domains = ['secur3-bank.com', 'payp4l-verify.net', 'g00gle-update.org']
        
        emails = []
        for i in range(count):
            template = random.choice(templates)
            domain = random.choice(sender_domains)
            malicious_url = f'http://phishing-{random.randint(100, 999)}.{domain}'
            
            content = template.format(malicious_url)
            content += f"\n\nFrom: noreply@{domain}"
            
            emails.append({'content': content, 'label': 'phishing', 'source': 'generated'})
        
        return emails
    
    def generate_legitimate_emails(self, count=2500):
        """Generate legitimate email dataset"""
        templates = [
            "Thank you for your recent purchase. Your order #{} has been confirmed.",
            "Your monthly statement is now available for download.",
            "Welcome to our service! Here's how to get started...",
            "Your subscription renews on {}. No action needed.",
            "New features have been added to your account.",
            "Here's your weekly newsletter with the latest updates."
        ]
        
        legitimate_domains = ['company.com', 'service.org', 'business.net']
        
        emails = []
        for i in range(count):
            template = random.choice(templates)
            domain = random.choice(legitimate_domains)
            
            if '{}' in template:
                if 'order' in template:
                    content = template.format(f"ORD{random.randint(100000, 999999)}")
                else:
                    content = template.format(datetime.now().strftime('%Y-%m-%d'))
            else:
                content = template
            
            content += f"\n\nFrom: support@{domain}"
            
            emails.append({'content': content, 'label': 'legitimate', 'source': 'generated'})
        
        return emails
    
    def generate_html_samples(self, count=1000):
        """Generate HTML sample dataset"""
        phishing_html_templates = [
            '<html><body><h1>Verify Your Account</h1><form action="http://phishing-site.com"><input type="password" name="pass"><button>Submit</button></form></body></html>',
            '<html><body><div>URGENT: Click <a href="http://malicious-site.net">here</a> to secure your account</div></body></html>',
            '<html><body><iframe src="http://suspicious-domain.com"></iframe><script>document.location="http://phishing.com"</script></body></html>'
        ]
        
        legitimate_html_templates = [
            '<html><body><h1>Welcome to Our Service</h1><p>Thank you for joining us!</p></body></html>',
            '<html><body><nav><ul><li><a href="/home">Home</a></li><li><a href="/about">About</a></li></ul></nav></body></html>',
            '<html><body><div class="content"><p>This is a legitimate website with proper structure.</p></div></body></html>'
        ]
        
        samples = []
        
        # Generate phishing HTML
        for i in range(count // 2):
            template = random.choice(phishing_html_templates)
            samples.append({'content': template, 'label': 'phishing', 'source': 'generated'})
        
        # Generate legitimate HTML
        for i in range(count // 2):
            template = random.choice(legitimate_html_templates)
            samples.append({'content': template, 'label': 'legitimate', 'source': 'generated'})
        
        return samples
    
    def populate_database(self):
        """Populate database with generated datasets"""
        from app import app
        
        with app.app_context():
            # Clear existing datasets
            MLDataset.query.delete()
            db.session.commit()
            
            # Generate and save URL datasets
            print("Generating URL datasets...")
            phishing_urls = self.generate_phishing_urls(3000)
            legitimate_urls = self.generate_legitimate_urls(3000)
            
            for url_data in phishing_urls + legitimate_urls:
                dataset = MLDataset(
                    dataset_type='url',
                    content=url_data['content'],
                    label=url_data['label'],
                    source=url_data['source'],
                    is_verified=True
                )
                db.session.add(dataset)
            
            # Generate and save email datasets
            print("Generating email datasets...")
            phishing_emails = self.generate_phishing_emails(2500)
            legitimate_emails = self.generate_legitimate_emails(2500)
            
            for email_data in phishing_emails + legitimate_emails:
                dataset = MLDataset(
                    dataset_type='email',
                    content=email_data['content'],
                    label=email_data['label'],
                    source=email_data['source'],
                    is_verified=True
                )
                db.session.add(dataset)
            
            # Generate and save HTML datasets
            print("Generating HTML datasets...")
            html_samples = self.generate_html_samples(1000)
            
            for html_data in html_samples:
                dataset = MLDataset(
                    dataset_type='html',
                    content=html_data['content'],
                    label=html_data['label'],
                    source=html_data['source'],
                    is_verified=True
                )
                db.session.add(dataset)
            
            db.session.commit()
            print(f"Successfully populated database with {MLDataset.query.count()} dataset entries")

if __name__ == '__main__':
    manager = DatasetManager()
    manager.populate_database()
