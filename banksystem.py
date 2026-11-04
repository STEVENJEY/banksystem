import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "galactic_vault_secure_key_2026")

# Database URI logic supporting PostgreSQL on Render and SQLite locally
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///banking.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Database Models matching tech stack guide
class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    pin = db.Column(db.String(50), nullable=False)
    balance = db.Column(db.Float, nullable=False, default=0.0)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)

def log_security_event(username, action, details):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log = AuditLog(username=username, action=action, details=details, timestamp=now)
    db.session.add(log)
    db.session.commit()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        pin = request.form['pin'].strip()
        role = request.form['role']

        if role == 'admin':
            if username == 'admin' and pin == '0000':
                session['user'] = 'admin'
                session['role'] = 'admin'
                log_security_event("admin", "Admin Authentication", "Terminal root access authorized.")
                return redirect('/admin')
            else:
                flash("Invalid administrator credentials.")
        else:
            user = User.query.filter_by(username=username, pin=pin).first()
            if user:
                session['user'] = user.username
                session['role'] = 'customer'
                log_security_event(user.username, "Customer Login", "Secure remote session established.")
                return redirect('/customer')
            else:
                flash("Invalid Account ID or Security PIN.")

    return render_template('login.html')

@app.route('/admin')
def admin_panel():
    if session.get('role') != 'admin':
        return redirect('/')
    logs = AuditLog.query.order_by(AuditLog.id.desc()).all()
    return render_template('admin.html', logs=logs)

@app.route('/admin/create_user', methods=['POST'])
def create_user():
    if session.get('role') != 'admin':
        return redirect('/')
    username = request.form['username'].strip()
    name = request.form['name'].strip()
    pin = request.form['pin'].strip()
    balance = float(request.form['balance'] or 0.0)

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash("Error: That Account ID already exists.")
        return redirect('/admin')

    try:
        new_user = User(username=username, name=name, pin=pin, balance=balance)
        db.session.add(new_user)
        db.session.commit()
        log_security_event("admin", "Account Provisioned", f"Created account {username} for {name} with ${balance:.2f}")
        flash(f"Account {username} initialized successfully.")
    except Exception:
        db.session.rollback()
        flash("An error occurred while creating the account.")
        
    return redirect('/admin')

@app.route('/customer')
def customer_panel():
    if session.get('role') != 'customer':
        return redirect('/')
    user = User.query.filter_by(username=session['user']).first()
    logs = AuditLog.query.filter_by(username=session['user']).order_by(AuditLog.id.desc()).all()
    return render_template('customer.html', user=user, logs=logs)

@app.route('/customer/transaction', methods=['POST'])
def process_transaction():
    if session.get('role') != 'customer':
        return redirect('/')
    
    action = request.form['action']
    amount = float(request.form['amount'])
    username = session['user']

    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect('/')

    if action == 'deposit':
        if amount > 0:
            user.balance += amount
            db.session.commit()
            log_security_event(username, "Deposit Execution", f"Deposited: ${amount:.2f}. Shield token active.")
            flash(f"Deposited: ${amount:.2f}. New Balance: ${user.balance:.2f}")
        else:
            flash("Invalid amount. Must be greater than zero.")
    
    elif action == 'withdraw':
        if 0 < amount <= user.balance:
            user.balance -= amount
            db.session.commit()
            log_security_event(username, "Withdrawal Execution", f"Withdrew: ${amount:.2f}. Firewall clear.")
            flash(f"Withdrawn: ${amount:.2f}. New Balance: ${user.balance:.2f}")
        elif amount > user.balance:
            log_security_event(username, "Security Event Refusal", f"Denied withdrawal of ${amount:.2f} due to insufficient funds.")
            flash("Error: Insufficient funds.")
        else:
            flash("Invalid amount. Must be greater than zero.")

    return redirect('/customer')

@app.route('/customer/change_pin', methods=['POST'])
def change_pin():
    if session.get('role') != 'customer':
        return redirect('/')
    new_pin = request.form['new_pin'].strip()
    username = session['user']

    user = User.query.filter_by(username=username).first()
    if user:
        user.pin = new_pin
        db.session.commit()
        log_security_event(username, "PIN Rotation", "Account security credential rotation successfully performed.")
        flash("PIN changed successfully.")
    return redirect('/customer')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
