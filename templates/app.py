from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.units import inch
import json
import re
from datetime import datetime
from urllib.parse import urlparse

class ForensicsAnalyzer:
    MALICIOUS_KEYWORDS = ['malware', 'phishing', 'command-control', 'c2', 'suspicious', 'stealer', 'beacon', 'ransomware', 'trojan', 'botnet', 'worm', 'virus', 'exploit', 'rootkit', 'spyware', 'adware', 'spam']
    RISKY_TLDS = ['.ru', '.cn', '.xyz', '.tk', '.ml', '.ga', '.cf', '.top']
    PHISHING_KEYWORDS = ['verify account', 'confirm identity', 'update payment', 'click here', 'urgent action', 'suspend', 'locked', 'unusual activity', 'act now', 'immediate action', 'update information', 'reset password']
    
    def analyze_email_headers(self, content):
        result = {'type': 'email', 'risk_score': 0.0, 'findings': [], 'details': {}}
        if not content or not content.strip():
            return result
        risk = 0
        headers = {}
        for line in content.split('\n'):
            if ':' in line and not line.startswith('\t') and not line.startswith(' '):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    headers[parts[0].strip().lower()] = parts[1].strip()
        if headers.get('dmarc-status', '').lower() == 'fail':
            risk += 3
            result['findings'].append('DMARC verification failed')
        if 'fail' in headers.get('spf', '').lower() or 'softfail' in headers.get('spf', '').lower():
            risk += 3
            result['findings'].append('SPF check failed')
        if 'missing' in headers.get('dkim-signature', '').lower():
            if headers.get('dkim-signature'):
                risk += 2
                result['findings'].append('DKIM signature missing or invalid')
        from_addr = headers.get('from', '')
        return_path = headers.get('return-path', '')
        if from_addr and return_path:
            from_domain = self._extract_domain(from_addr)
            return_domain = self._extract_domain(return_path)
            if from_domain and return_domain and from_domain != return_domain:
                risk += 4
                result['findings'].append('Spoofed sender: From ({}) != Return-Path ({})'.format(from_domain, return_domain))
        for header_key in ['from', 'return-path']:
            addr = headers.get(header_key, '')
            if addr:
                domain = self._extract_domain(addr)
                if domain:
                    if self._is_risky_domain(domain):
                        risk += 2
                        result['findings'].append('Suspicious domain in {}: {}'.format(header_key, domain))
                    if self._is_spoofed_domain(domain):
                        risk += 3
                        result['findings'].append('Spoofed domain detected in {}: {}'.format(header_key, domain))
        subject = headers.get('subject', '').lower()
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in subject:
                risk += 2
                result['findings'].append('Phishing keyword in subject: "{}"'.format(keyword))
                break
        originating_ip = headers.get('x-originating-ip', '')
        if originating_ip:
            if '192.168' in originating_ip or '10.0' in originating_ip:
                risk += 1
                result['findings'].append('Email from private IP range')
        priority = headers.get('x-priority', '3')
        if priority in ['1', '2']:
            risk += 1
            result['findings'].append('Unusual high priority flag')
        result['risk_score'] = min(risk, 10.0)
        result['details'] = {'auth_status': {'dmarc': headers.get('dmarc-status', 'unknown'), 'spf': headers.get('spf', 'unknown'), 'dkim': 'present' if headers.get('dkim-signature') else 'missing'}}
        return result
    
    def analyze_browser_logs(self, content):
        result = {'type': 'browser', 'risk_score': 0.0, 'findings': [], 'details': {}}
        if not content or not content.strip():
            return result
        risk = 0
        detected_domains = set()
        for line in content.split('\n'):
            if not line.strip():
                continue
            line_lower = line.lower()
            for keyword in self.MALICIOUS_KEYWORDS:
                if keyword in line_lower:
                    risk += 3
                    result['findings'].append('Detected malicious keyword: {}'.format(keyword))
                    break
            domains = self._extract_urls_and_domains(line)
            for domain in domains:
                if domain not in detected_domains:
                    domain_risk = self._evaluate_domain_risk(domain)
                    risk += domain_risk
                    if domain_risk > 0:
                        result['findings'].append('Suspicious domain: {} (risk: +{})'.format(domain, domain_risk))
                    detected_domains.add(domain)
            if re.search(r'\.(exe|dll|bat|cmd|scr|msi|zip|rar|7z|dmg|pkg)\b', line_lower):
                risk += 3
                result['findings'].append('Executable or archive file detected')
            if 'http://' in line_lower and 'https' not in line_lower:
                if 'login' in line_lower or 'password' in line_lower or 'credential' in line_lower:
                    risk += 2
                    result['findings'].append('Credentials over unencrypted HTTP detected')
            if 'user-agent' in line_lower and ('obfuscated' in line_lower or 'bot' in line_lower or 'curl' in line_lower):
                risk += 1
                result['findings'].append('Suspicious user agent detected')
        result['risk_score'] = min(risk, 10.0)
        result['details'] = {'detected_domains': list(detected_domains)}
        return result
    
    def _extract_urls_and_domains(self, log_line):
        domains = set()
        url_pattern = r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)'
        for match in re.finditer(url_pattern, log_line):
            domain = match.group(1).lower()
            if '.' in domain and len(domain) > 3:
                if not domain.startswith('192.168') and not domain.startswith('10.0') and not domain.startswith('127.0'):
                    domains.add(domain)
        return domains
    
    def _extract_domain(self, email_or_addr):
        addr = email_or_addr.strip().strip('<>')
        if '@' in addr:
            return addr.split('@')[1].lower()
        try:
            parsed = urlparse(addr if addr.startswith('http') else 'http://{}'.format(addr))
            return parsed.netloc.lower()
        except:
            return None
    
    def _is_risky_domain(self, domain):
        domain_lower = domain.lower()
        for tld in self.RISKY_TLDS:
            if domain_lower.endswith(tld):
                return True
        return False
    
    def _is_spoofed_domain(self, domain):
        domain_lower = domain.lower()
        spoofing_patterns = [('paypal', ['paypal-', 'paypa1-', 'pp-', 'pp-verify']), ('amazon', ['amazon-', 'amaz0n-', 'amazo-']), ('apple', ['apple-', 'appl3-', 'icloud-']), ('microsoft', ['microsoft-', 'msft-', 'live-']), ('google', ['google-', 'goog1e-', 'gmail-'])]
        for legitimate, spoofing_vars in spoofing_patterns:
            for spoof_pattern in spoofing_vars:
                if spoof_pattern in domain_lower and legitimate not in domain_lower:
                    return True
        return False
    
    def _evaluate_domain_risk(self, domain):
        risk = 0
        domain_lower = domain.lower()
        if self._is_risky_domain(domain):
            risk += 2
        if self._is_spoofed_domain(domain):
            risk += 3
        for keyword in ['phish', 'malware', 'exploit', 'spam', 'fraud', 'steal', 'command', 'control', 'beacon', 'download']:
            if keyword in domain_lower:
                risk += 3
                break
        return risk

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forensics.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    security_question = db.Column(db.String(255), nullable=False)
    security_answer = db.Column(db.String(255), nullable=False)
    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(20), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def validate_username(username):
    if not username or len(username) < 3 or len(username) > 20:
        return False, "Username must be 3-20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscore"
    return True, "OK"

def validate_password(password):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must include at least 1 uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must include at least 1 lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must include at least 1 number"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Password must include at least 1 special character"
    return True, "OK"

security_questions = ["What is your favorite color?", "What is your mother's maiden name?", "What was the name of your first pet?", "What city were you born in?", "What is your favorite book?", "What was your first car?", "What is your favorite movie?", "What is your best friend's name?"]

@app.route('/')
@login_required
def index():
    scans = current_user.scans
    return render_template('index.html', scans=scans)

@app.route('/dashboard')
@login_required
def dashboard():
    scans = current_user.scans
    return render_template('index.html', scans=scans)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            return render_template('login.html', error="Username and password required")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        security_question = request.form.get('security_question', '')
        security_answer = request.form.get('security_answer', '').strip().lower()
        is_valid, msg = validate_username(username)
        if not is_valid:
            return render_template('signup.html', error=msg, questions=security_questions)
        if User.query.filter_by(username=username).first():
            return render_template('signup.html', error="Username already exists", questions=security_questions)
        is_valid, msg = validate_password(password)
        if not is_valid:
            return render_template('signup.html', error=msg, questions=security_questions)
        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match", questions=security_questions)
        if not security_question or not security_answer:
            return render_template('signup.html', error="Please select a security question and answer", questions=security_questions)
        user = User(username=username, password=generate_password_hash(password), security_question=security_question, security_answer=security_answer)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html', questions=security_questions)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template('forgot_password.html', error="Username not found")
        return redirect(url_for('verify_answer', username=username))
    return render_template('forgot_password.html')

@app.route('/verify_answer', methods=['GET', 'POST'])
def verify_answer():
    username = request.args.get('username') or request.form.get('username')
    if not username:
        return redirect(url_for('forgot_password'))
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        answer = request.form.get('security_answer', '').strip().lower()
        if answer == user.security_answer:
            return redirect(url_for('reset_password', username=username))
        else:
            return render_template('verify_answer.html', question=user.security_question, error="Incorrect answer", username=username)
    return render_template('verify_answer.html', question=user.security_question, username=username)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    username = request.args.get('username') or request.form.get('username')
    if not username:
        return redirect(url_for('forgot_password'))
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        is_valid, msg = validate_password(password)
        if not is_valid:
            return render_template('reset_password.html', error=msg, username=username)
        if password != confirm_password:
            return render_template('reset_password.html', error="Passwords do not match", username=username)
        user.password = generate_password_hash(password)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('reset_password.html', username=username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/scan_email', methods=['POST'])
@login_required
def scan_email():
    content = request.form.get('email_headers')
    analyzer = ForensicsAnalyzer()
    result = analyzer.analyze_email_headers(content)
    scan_record = Scan(user_id=current_user.id, scan_type='email', risk_score=result['risk_score'], details=json.dumps(result))
    db.session.add(scan_record)
    db.session.commit()
    return render_template('report.html', result=result, scan=scan_record)

@app.route('/scan_browser', methods=['POST'])
@login_required
def scan_browser():
    content = request.form.get('browser_logs')
    analyzer = ForensicsAnalyzer()
    result = analyzer.analyze_browser_logs(content)
    scan_record = Scan(user_id=current_user.id, scan_type='browser', risk_score=result['risk_score'], details=json.dumps(result))
    db.session.add(scan_record)
    db.session.commit()
    return render_template('report.html', result=result, scan=scan_record)

@app.route('/report/<int:scan_id>')
@login_required
def view_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return redirect(url_for('index'))
    result = json.loads(scan.details)
    return render_template('report.html', result=result, scan=scan)

@app.route('/report/<int:scan_id>/download')
@login_required
def download_report(scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        return "Report not found", 404
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=20, textColor='#333333', spaceAfter=20, alignment=1)
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, textColor='#667eea', spaceAfter=12, spaceBefore=12)
    normal_style = styles['Normal']
    story = []
    story.append(Paragraph("Forensics Analysis Report", title_style))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("<b>Risk Score:</b> {}/10".format(scan.risk_score), normal_style))
    story.append(Paragraph("<b>Scan Type:</b> {}".format(scan.scan_type), normal_style))
    story.append(Paragraph("<b>Date:</b> {}".format(scan.timestamp), normal_style))
    story.append(Spacer(1, 0.2*inch))
    try:
        details = json.loads(scan.details)
        story.append(Paragraph("Risk Assessment", heading_style))
        if details.get('risk_score', 0) >= 7:
            risk_level = "CRITICAL - Immediate action required"
        elif details.get('risk_score', 0) >= 5:
            risk_level = "HIGH - Review and take action"
        elif details.get('risk_score', 0) >= 3:
            risk_level = "MEDIUM - Monitor"
        else:
            risk_level = "LOW - Generally safe"
        story.append(Paragraph(risk_level, normal_style))
        story.append(Spacer(1, 0.15*inch))
        if 'findings' in details:
            story.append(Paragraph("Key Findings", heading_style))
            for finding in details['findings']:
                story.append(Paragraph("• " + str(finding), normal_style))
            story.append(Spacer(1, 0.15*inch))
        story.append(Paragraph("Detailed Analysis", heading_style))
        if 'details' in details and isinstance(details['details'], dict):
            for key, value in details['details'].items():
                story.append(Paragraph("<b>{}:</b> {}".format(key.replace('_', ' ').title(), str(value)[:150]), normal_style))
    except Exception as e:
        story.append(Paragraph("Error: " + str(e), normal_style))
    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="report_{}.pdf".format(scan_id), mimetype="application/pdf")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)