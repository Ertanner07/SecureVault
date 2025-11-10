"""
SecureVault - Flask Password Manager
Connects to PHPMyAdmin MySQL Database: securevault
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet
import MySQLdb.cursors
import secrets
import os
from datetime import timedelta, datetime
from functools import wraps

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'securevault'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Encryption
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key()
    print(f"\n SAVE THIS KEY: {ENCRYPTION_KEY.decode()}\n")
else:
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

cipher_suite = Fernet(ENCRYPTION_KEY)

# Track failed login attempts
failed_attempts = {}
locked_accounts = {}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def encrypt_password(password):
    """Encrypt password using Fernet"""
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    """Decrypt password"""
    try:
        return cipher_suite.decrypt(encrypted_password.encode()).decode()
    except:
        return "[Decryption Error]"

def is_account_locked(identifier):
    """Check if account is locked"""
    if identifier in locked_accounts:
        if datetime.now() < locked_accounts[identifier]:
            remaining = (locked_accounts[identifier] - datetime.now()).seconds // 60
            return True, remaining
        else:
            del locked_accounts[identifier]
            failed_attempts[identifier] = 0
    return False, 0

def record_failed_attempt(identifier):
    """Record failed login attempt"""
    failed_attempts[identifier] = failed_attempts.get(identifier, 0) + 1
    if failed_attempts[identifier] >= 5:
        locked_accounts[identifier] = datetime.now() + timedelta(minutes=15)
        return True, 15
    return False, 5 - failed_attempts[identifier]

def reset_failed_attempts(identifier):
    """Reset on successful login"""
    failed_attempts[identifier] = 0
    if identifier in locked_accounts:
        del locked_accounts[identifier]

def require_login(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        last_activity = session.get('last_activity')
        if last_activity:
            last_time = datetime.fromisoformat(last_activity)
            if datetime.now() - last_time > timedelta(minutes=30):
                session.clear()
                flash('Session expired. Please log in again.', 'info')
                return redirect(url_for('login'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

# ============================================================
# ROUTES
# ============================================================

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=['POST'])
def login():
    """Login page and authentication"""
    if request.method == 'GET':
        return render_template('index.html')
    
    username = request.form.get('username', '').strip().lower()
    password = request.form.get('password', '')
    ip_address = request.remote_addr
    identifier = f"{username}_{ip_address}"
    
    # Check if locked
    is_locked, remaining = is_account_locked(identifier)
    if is_locked:
        flash(f'Account locked. Try again in {remaining} minutes.', 'danger')
        return render_template('index.html')
    
    try:
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        
        if user and check_password_hash(user['password_hash'], password):
            # Success
            reset_failed_attempts(identifier)
            session.permanent = True
            session['username'] = username
            session['user_id'] = user['id']
            session['login_time'] = datetime.now().isoformat()
            session['last_activity'] = datetime.now().isoformat()
            
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('vault'))
        else:
            # Failure
            is_locked, attempts_left = record_failed_attempt(identifier)
            if is_locked:
                flash('Too many failed attempts. Locked for 15 minutes.', 'danger')
            else:
                flash(f'Invalid credentials. {attempts_left} attempts remaining.', 'danger')
            return render_template('index.html')
            
    except Exception as e:
        print(f"Database error: {e}")
        flash('Database connection error. Check MySQL is running.', 'danger')
        return render_template('index.html')


@app.route('/vault')
@require_login
def vault():
    """Display password vault"""
    username = session['username']
    
    try:
        cursor = mysql.connection.cursor()
        cursor.execute('''
            SELECT v.*
            FROM vault_entries v
            JOIN users u ON v.user_id = u.id
            WHERE u.username = %s
            ORDER BY v.created_at DESC
        ''', (username,))
        entries = cursor.fetchall()
        cursor.close()
        
        # Decrypt passwords
        for entry in entries:
            entry['decrypted_password'] = decrypt_password(entry['encrypted_password'])
        
        login_time = datetime.fromisoformat(session.get('login_time'))
        session_age = datetime.now() - login_time
        time_remaining = timedelta(minutes=30) - session_age
        minutes_remaining = max(0, int(time_remaining.total_seconds() / 60))
        
        return render_template('vault.html', 
                             username=username, 
                             entries=entries,
                             session_minutes_remaining=minutes_remaining)
    except Exception as e:
        print(f"Error loading vault: {e}")
        flash(f'Error loading vault: {e}', 'danger')
        return redirect(url_for('login'))


@app.route('/add_entry', methods=['POST'])
@require_login
@limiter.limit("10 per minute")
def add_entry():
    """Add new password entry"""
    site_name = request.form.get('site', '').strip()
    site_username = request.form.get('site_username', '').strip()
    password = request.form.get('password', '')
    
    if not all([site_name, site_username, password]):
        flash('All fields are required.', 'warning')
        return redirect(url_for('vault'))
    
    try:
        encrypted_password = encrypt_password(password)
        cursor = mysql.connection.cursor()
        cursor.execute(
            'INSERT INTO vault_entries (user_id, site_name, site_username, encrypted_password) VALUES (%s, %s, %s, %s)',
            (session['user_id'], site_name, site_username, encrypted_password)
        )
        mysql.connection.commit()
        cursor.close()
        
        flash(f'Password for {site_name} encrypted and saved!', 'success')
    except Exception as e:
        flash(f'Error saving entry: {e}', 'danger')
    
    return redirect(url_for('vault'))


@app.route('/delete_entry/<int:entry_id>')
@require_login
def delete_entry(entry_id):
    """Delete password entry"""
    try:
        cursor = mysql.connection.cursor()
        cursor.execute(
            'DELETE FROM vault_entries WHERE id = %s AND user_id = %s',
            (entry_id, session['user_id'])
        )
        mysql.connection.commit()
        affected = cursor.rowcount
        cursor.close()
        
        if affected > 0:
            flash('Entry deleted successfully.', 'success')
        else:
            flash('Entry not found.', 'danger')
    except Exception as e:
        flash(f'Error deleting entry: {e}', 'danger')
    
    return redirect(url_for('vault'))


@app.route('/logout')
def logout():
    """Logout"""
    username = session.get('username', 'Unknown')
    session.clear()
    flash('You have been logged out.', 'info')
    print(f"Logout: {username}")
    return redirect(url_for('login'))


if __name__ == '__main__':
    print(f"""
-------------------------------------------------------------
 SecureVault Starting...
-------------------------------------------------------------
 Database : {app.config['MYSQL_DB']}
 Host     : {app.config['MYSQL_HOST']}
 Port     : {app.config['MYSQL_PORT']}

 URLs:
  • Login : http://127.0.0.1:5000
  • Vault : http://127.0.0.1:5000/vault

 Test Accounts:
  • admin / admin123
  • techguru / tech456
  • analyst1 / analyst789
-------------------------------------------------------------
""")
    app.run(host='0.0.0.0', port=5000, debug=True)

