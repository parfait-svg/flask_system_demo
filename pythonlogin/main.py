from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import re
import hashlib
import os
import time
from werkzeug.utils import secure_filename

# -------------------------
# App & DB configuration
# -------------------------
app = Flask(__name__)
app.secret_key = 'your secret key'   # keep same, used for hashing passwords


DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'mysql-69cb52a-parfaitbrisco-2d03.f.aivencloud.com'),
    'user': os.environ.get('DB_USER', 'avnadmin'),
    'password': os.environ.get('DB_PASSWORD', 'AVNS_z6Gc26JSkrI9XUHEPpj'),
    'database': os.environ.get('DB_NAME', 'defaultdb'),
    'port': int(os.environ.get('DB_PORT', 24776))
}


# Upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB max

# -------------------------
# Helpers
# -------------------------
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def hash_password(password):
    return hashlib.sha1((password + app.secret_key).encode()).hexdigest()

# -------------------------
# Login route
# -------------------------
@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM accounts WHERE username=%s AND password=%s', (username, hashed_password))
        account = cursor.fetchone()
        cursor.close()
        conn.close()

        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['is_admin'] = account.get('is_admin', 0)
            return redirect(url_for('home'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)

# -------------------------
# Logout
# -------------------------
@app.route('/pythonlogin/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# -------------------------
# Register
# -------------------------
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and all(k in request.form for k in ('username', 'password', 'email')):
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM accounts WHERE username=%s', (username,))
        account = cursor.fetchone()

        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must be alphanumeric!'
        elif not username or not password or not email:
            msg = 'Please fill out all fields!'
        else:
            hashed_password = hash_password(password)
            cursor.execute('INSERT INTO accounts (username, password, email) VALUES (%s, %s, %s)',
                           (username, hashed_password, email))
            conn.commit()
            msg = 'You have successfully registered!'
        cursor.close()
        conn.close()
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)

# -------------------------
# Home
# -------------------------
@app.route('/pythonlogin/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'], is_admin=session.get('is_admin', 0))
    return redirect(url_for('login'))

# -------------------------
# Profile
# -------------------------
@app.route('/pythonlogin/profile')
def profile():
    if 'loggedin' in session:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM accounts WHERE id=%s', (session['id'],))
        account = cursor.fetchone()
        cursor.close()
        conn.close()
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))

# -------------------------
# Edit profile
# -------------------------
@app.route('/pythonlogin/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    msg = ''
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        fullname = request.form.get('fullname', '').strip()
        phone = request.form.get('phone', '').strip()
        file = request.files.get('profile_pic')
        filename_db = None

        if file and file.filename != '':
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"user_{session['id']}_{int(time.time())}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                filename_db = filename
            else:
                msg = 'Invalid file type!'

        if msg == '':
            if filename_db:
                cursor.execute('UPDATE accounts SET fullname=%s, phone=%s, profile_pic=%s WHERE id=%s',
                               (fullname, phone, filename_db, session['id']))
            else:
                cursor.execute('UPDATE accounts SET fullname=%s, phone=%s WHERE id=%s',
                               (fullname, phone, session['id']))
            conn.commit()
            msg = 'Profile updated successfully!'

    cursor.execute('SELECT * FROM accounts WHERE id=%s', (session['id'],))
    account = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('edit_profile.html', account=account, msg=msg)


@app.route('/pythonlogin/admin_dashboard')
def admin_dashboard():
    if 'loggedin' in session and session.get('is_admin', False):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT id, username, email FROM accounts')
        users = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('admin_dashboard.html', users=users)
    return redirect(url_for('admin_login'))


# -------------------------
# Admin login route
# -------------------------
@app.route('/pythonlogin/admin_login', methods=['GET', 'POST'])
def admin_login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        # Check if credentials match the admin
        if username == 'brice' and password == '2000':
            session['loggedin'] = True
            session['username'] = 'brice'
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            msg = 'Incorrect admin credentials!'
    return render_template('admin_login.html', msg=msg)


# -------------------------
# Run app
# -------------------------
if __name__ == '__main__':
    app.run(debug=True, port=5050)
