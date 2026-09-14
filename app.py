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
    MALICIOUS_KEYWORDS = ['malware', 'phishing', 'command-control', 'c2', 'suspicious', 'stealer', 'beacon', 'ransomware', 'trojan', 'botnet', 'worm', 'virus', 'exploit', 'rootkit', 'spyware', 'adware', 'spam', 'payload', 'download']
    RISKY_TLDS = ['.ru', '.cn', '.xyz', '.tk', '.ml', '.ga', '.cf', '.top']
    PHISHING_KEYWORDS = ['verify account', 'confirm identity', 'update payment', 'click here', 'urgent action', 'suspend', 'locked', 'unusual activity', 'act now', 'immediate action', 'update information', 'reset password']
    
    def analyze_email_headers(self, content):
        result = {'type': 'email', 'risk_score': 0.0, 'findings': []}
        if not content or not content.strip():
            return result
        risk = 0
        headers = {}
        for line in content.split('\n'):
            if ':' in line and not line.startswith('\t'):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    headers[parts[0].strip().lower()] = parts[1].strip()
        if headers.get('dmarc-status', '').lower() == 'fail':
            risk += 3
            result['findings'].append('DMARC verification failed')
        if 'fail' in headers.get('spf', '').lower():
            risk += 3
            result['findings'].append('SPF check failed')
        from_addr = headers.get('from', '')
        return_path = headers.get('return-path', '')
        if from_addr and return_path:
            if from_addr.split('@')[1:] != return_path.split('@')[1:]:
                risk += 4
                result['findings'].append('Spoofed sender detected')
        subject = headers.get('subject', '').lower()
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in subject:
                risk += 2
                result['findings'].append('Phishing keyword detected')
                break
        result['risk_score'] = min(risk, 10.0)
        return result
    
    def analyze_browser_logs(self, content):
        result = {'type': 'browser', 'risk_score': 0.0, 'findings': []}
        if not content or not content.strip():
            return result
        risk = 0
        for line in content.split('\n'):
            line_lower = line.lower()
            for keyword in self.MALICIOUS_KEYWORDS:
                if keyword in line_lower:
                    risk += 3
                    result['findings'].append('Malicious keyword: {}'.format(keyword))
                    break
            if 'http://' in line_lower and 'https://' not in line_lower:
                risk += 2
                result['findings'].append('Unencrypted HTTP detected')
            if '.ru' in line_lower:
                risk += 2
                result['findings'].append('Risky .ru domain detected')
            if '.xyz' in line_lower:
                risk += 2
                result['findings'].append('Risky .xyz domain detected')
            if '.exe' in line_lower or '.dll' in line_lower or '.zip' in line_lower:
                risk += 3
                result['findings'].append('Executable file detected')
        result['risk_score'] = min(risk, 10.0)
        return result

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
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
    scans = db.relationship('Scan', backref='user', lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    scan_type = db.Column(db.String(20))
    risk_score = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

security_questions = ["What is your favorite color?", "What is your mother's maiden name?", "What was the name of your first pet?", "What city were you born in?", "What is your favorite book?", "What was your first car?", "What is your favorite movie?", "What is your best friend's name?"]

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    return render_template('index.html', scans=current_user.scans)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html', scans=current_user.scans)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        security_question = request.form.get('security_question', '').strip()
        security_answer = request.form.get('security_answer', '').strip().lower()
        
        if password != confirm_password:
            return render_template('signup.html', error="Passwords don't match", questions=security_questions)
        
        if User.query.filter_by(username=username).first():
            return render_template('signup.html', error="Username exists", questions=security_questions)
        
        user = User(
            username=username,
            password=generate_password_hash(password),
            security_question=security_question,
            security_answer=security_answer
        )
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
            return render_template('forgot_password.html', error="Not found")
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
        return render_template('verify_answer.html', question=user.security_question, error="Wrong", username=username)
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
        confirm = request.form.get('confirm_password', '')
        if password != confirm:
            return render_template('reset_password.html', error="Don't match", username=username)
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
    scan = Scan(user_id=current_user.id, scan_type='email', risk_score=result['risk_score'], details=json.dumps(result))
    db.session.add(scan)
    db.session.commit()
    return render_template('report.html', result=result, scan=scan)

@app.route('/scan_browser', methods=['POST'])
@login_required
def scan_browser():
    content = request.form.get('browser_logs')
    analyzer = ForensicsAnalyzer()
    result = analyzer.analyze_browser_logs(content)
    scan = Scan(user_id=current_user.id, scan_type='browser', risk_score=result['risk_score'], details=json.dumps(result))
    db.session.add(scan)
    db.session.commit()
    return render_template('report.html', result=result, scan=scan)

@app.route('/report/<int:scan_id>')
@login_required
def view_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return redirect(url_for('index'))
    result = json.loads(scan.details)
    return render_template('report.html', result=result, scan=scan)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)