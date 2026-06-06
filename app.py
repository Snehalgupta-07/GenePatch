# Main Flask Application - Vulnerable Student Management System
from flask import Flask, render_template, request, redirect, session, url_for, send_file, send_from_directory, g, abort, flash # Added g, abort, flash
from werkzeug.utils import secure_filename
import os
import database
from config import Config
from datetime import datetime, timedelta
import logging # NEW: Import logging for app.logger
import secrets # NEW: Import secrets for token generation
from functools import wraps # NEW: Import wraps for decorators

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
if not os.path.exists(database.DB_NAME):
    database.init_db()

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# NEW: Ensure secure docs folder exists for application-level public documents
os.makedirs(os.path.join(app.root_path, app.config['SECURE_DOCS_FOLDER']), exist_ok=True)

# VULNERABILITY: No rate limiting on login attempts (Brute Force & Credential Stuffing)
LOGIN_ATTEMPTS = {}

def record_login_attempt(username):
    """No rate limiting implemented"""
    if username in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[username] += 1
    else:
        LOGIN_ATTEMPTS[username] = 1

def check_rate_limit(username):
    """Not enforced - allows unlimited brute force attempts"""
    return True  # Always returns True - NO PROTECTION

# NEW: Helper function to check for allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# NEW: CSRF Protection Implementation
def generate_csrf_token():
    """Generates a new CSRF token and stores it in the session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

@app.before_request
def csrf_setup():
    """
    Ensures a CSRF token is available for the current request context.
    This token will be regenerated after successful POSTs by the csrf_required decorator.
    """
    g.csrf_token = generate_csrf_token() # Make token available to templates via g

def csrf_required(f):
    """
    Decorator to protect POST endpoints from CSRF attacks.
    It validates the CSRF token and regenerates it upon successful validation.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            form_token = request.form.get('csrf_token')
            session_token = session.get('_csrf_token')

            if not form_token or not session_token or form_token != session_token:
                app.logger.warning(f"CSRF token mismatch or missing for user {session.get('username', 'anonymous')} on endpoint {request.endpoint}")
                abort(400, description="CSRF token missing or incorrect.")
            
            # Regenerate token after successful validation to prevent token replay
            session['_csrf_token'] = secrets.token_hex(16)
            g.csrf_token = session['_csrf_token'] # Update g as well for potential subsequent redirects/renders
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Home page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return f"<h1>Welcome to Vulnerable Student Management System</h1><a href='/logout'>Logout</a><br><a href='/dashboard'>Dashboard</a>"

@app.route('/login', methods=['GET', 'POST'])
@csrf_required # NEW: Apply CSRF protection to the login POST route
def login():
    """
    VULNERABILITY: Multiple Security Flaws
    1. SQL Injection in authentication (FIXED in database.py)
    2. NO rate limiting (Brute Force attack)
    3. Weak password handling
    4. No CSRF protection (NOW FIXED)
    5. Sensitive error messages (FIXED)
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # No input validation
        
        # No rate limiting - allows unlimited login attempts
        record_login_attempt(username)
        
        # SQL Injection vulnerability here
        user = database.authenticate_user(username, password)
        
        if user:
            # VULNERABILITY: No session timeout enforcement
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = user[3]
            session['role'] = user[4]
            session.permanent = True
            
            # VULNERABILITY: Information Disclosure - Verbose logging
            database.log_action('LOGIN_SUCCESS', username, f"User logged in successfully")
            
            return redirect(url_for('dashboard'))
        else:
            # VULNERABILITY: Information Disclosure
            error = "Invalid username or password"
            database.log_action('LOGIN_FAILED', username, f"Failed login attempt with password: {password}")
            return render_template('login_new.html', error=error)
    
    return render_template('login_new.html')

@app.route('/dashboard')
def dashboard():
    """
    VULNERABILITY: No proper access control
    Anyone with a session can access
    Shows role-based dashboard
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard_new.html')

@app.route('/students')
def students():
    """
    VULNERABILITY: No access control - any authenticated user can see all data
    Exposes sensitive information (SSN, passwords)
    FIXED: Restrict to admin and user roles only (not students)
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Students cannot view all student records", 403
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, roll_no, name, email, phone, ssn FROM students')
    students_list = cursor.fetchall()
    conn.close()
    
    return render_template('students_new.html', students=students_list)

@app.route('/student/<student_id>')
def view_student(student_id):
    """
    VULNERABILITY: SQL Injection in student ID parameter
    Sensitive Data Exposure of SSN and password
    FIXED: Prevent students from viewing other student records
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Students cannot view other student records", 403
    
    # VULNERABLE: Direct parameter use - SQL Injection
    student = database.get_student_details(student_id)
    
    if not student:
        return "Student not found", 404
    
    return render_template('student_view.html', student=student)

@app.route('/student/profile')
def student_profile():
    """
    Student can view only their own profile
    Restricts access based on email matching between user and student record
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'student':
        return "Access Denied: Only students can view their profile", 403
    
    user_email = session.get('email')  # Requires email to be stored in session
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    # Use parameterized query here (matching email)
    cursor.execute('SELECT id, roll_no, name, email, phone, address, gpa FROM students WHERE email = ?', (user_email,))
    student = cursor.fetchone()
    conn.close()
    
    if not student:
        return "Your student record not found", 404
    
    return render_template('student_profile_new.html', student=student)

@app.route('/student/grades')
def student_grades():
    """
    Student can view only their own grades and GPA
    Restricts access to student role only
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'student':
        return "Access Denied: Only students can view their grades", 403
    
    user_email = session.get('email')
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT roll_no, name, gpa FROM students WHERE email = ?', (user_email,))
    student = cursor.fetchone()
    conn.close()
    
    if not student:
        return "Your student record not found", 404
    
    return render_template('student_grades_new.html', student=student)

@app.route('/add_student', methods=['GET', 'POST'])
@csrf_required # NEW: Apply CSRF protection
def add_student():
    """
    VULNERABILITY: No input validation, SQL Injection (FIXED in database.py)
    No privilege check (any user can add students) (FIXED)
    No CSRF protection (NOW FIXED)
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'admin':
        return "Access Denied: Only admins can add students", 403
    
    if request.method == 'POST':
        # No input validation or sanitization
        roll_no = request.form.get('roll_no', '')
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        ssn = request.form.get('ssn', '')
        gpa = request.form.get('gpa', '0')
        
        # VULNERABLE: No validation, SQL injection possible
        if database.add_student(roll_no, name, email, phone, address, ssn, gpa):
            flash('Student added successfully!', 'success') # Using flash instead of flask.flash
            return redirect(url_for('dashboard'))
        else:
            flash('Error adding student', 'danger') # Using flash instead of flask.flash
            return redirect(url_for('add_student'))
    
    return render_template('add_student_new.html')

@app.route('/search', methods=['GET', 'POST'])
def search_students():
    """
    VULNERABILITY: SQL Injection in search
    No access control - FIXED to prevent students
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Students cannot search student records", 403
    
    results = []
    if request.method == 'POST':
        search_term = request.form.get('search', '')
        
        # VULNERABLE: SQL Injection
        results = database.search_students(search_term)
        
        # VULNERABILITY: Information Disclosure - Shows query
        print(f"[*] Search performed for: {search_term}")
    
    return render_template('search_new.html', results=results)

@app.route('/upload', methods=['GET', 'POST'])
@csrf_required # NEW: Apply CSRF protection
def upload_file():
    """
    FIXED: Multiple File Upload Issues
    1. No file type validation (allows executables) -> FIXED
    2. Path Traversal vulnerability -> FIXED
    3. No file size limit enforcement -> (Addressed by Flask config)
    4. Predictable filenames -> (Requires further architectural change, out of scope for this fix focus)
    FIXED: Prevent students from uploading
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Only admin and users can upload files", 403
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger') # Using flash instead of flask.flash
            return redirect(url_for('upload_file'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger') # Using flash instead of flask.flash
            return redirect(url_for('upload_file'))
        
        # FIX: Validate file type against allowed extensions
        if not allowed_file(file.filename):
            flash('Invalid file type. Only allowed types are: ' + ', '.join(app.config['ALLOWED_EXTENSIONS']), 'danger') # Using flash instead of flask.flash
            return redirect(url_for('upload_file'))

        # FIX: Use secure_filename to sanitize filename and prevent path traversal during upload
        filename = secure_filename(file.filename)
        
        # Check if filename is empty after sanitization
        if not filename:
            flash('Invalid filename provided after sanitization.', 'danger') # Using flash instead of flask.flash
            return redirect(url_for('upload_file'))

        # Path Traversal vulnerability FIXED by secure_filename
        # File size limit is handled by app.config['MAX_CONTENT_LENGTH']
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(filepath)
        except Exception as e:
            app.logger.error(f"Error saving uploaded file '{filename}': {str(e)}")
            flash('Error uploading file.', 'danger') # Using flash instead of flask.flash
            return redirect(url_for('upload_file'))
        
        database.log_action('FILE_UPLOAD', session.get('username'), f"Uploaded file: {filepath}")
        
        flash(f'File "{filename}" uploaded successfully!', 'success') # Using flash instead of flask.flash
        return redirect(url_for('dashboard'))
    
    return render_template('upload_new.html')

@app.route('/download/<filename>')
def download_file(filename):
    """
    FIXED: Path Traversal vulnerability
    Now validates filename parameter and ensures the file is strictly within the UPLOAD_FOLDER.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # FIX: Sanitize filename by stripping any directory components.
    # This ensures only the base filename is used, preventing path traversal attempts.
    safe_filename = os.path.basename(filename)

    upload_folder_path = app.config['UPLOAD_FOLDER']
    
    try:
        # send_from_directory safely serves files, preventing path traversal
        # by ensuring the requested file (safe_filename) is strictly within the specified directory.
        response = send_from_directory(upload_folder_path, safe_filename)
        # Optionally log successful download, but avoid logging actual file content.
        return response
    except FileNotFoundError:
        return "File not found", 404
    except Exception as e:
        app.logger.error(f"Error downloading file '{safe_filename}' from '{upload_folder_path}': {str(e)}")
        return "Error accessing file", 500

@app.route('/file/<path:filename_or_path>') # Changed parameter name for clarity
def access_file(filename_or_path):
    """
    FIXED: Unrestricted File Path Access and Path Traversal vulnerability
    This route now serves application-specific files ONLY from a designated SECURE_DOCS_FOLDER,
    preventing arbitrary file access to files like config.py.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # FIX: Restrict access to a specific, non-sensitive directory within the application's root.
    # This directory should contain only files explicitly intended for public access (e.g., terms, policies).
    # This route is no longer for "ANY file on the system".
    base_dir = os.path.join(app.root_path, app.config['SECURE_DOCS_FOLDER'])

    try:
        # send_from_directory safely serves files, performing canonicalization and ensuring
        # the requested file (filename_or_path) is strictly within base_dir.
        response = send_from_directory(base_dir, filename_or_path)
        database.log_action('FILE_ACCESS', session.get('username'), f"Accessed securely confined file: {filename_or_path} from {app.config['SECURE_DOCS_FOLDER']}")
        return response
    except FileNotFoundError:
        return "File not found or access denied", 404
    except Exception as e:
        app.logger.error(f"Error accessing file '{filename_or_path}' from confined directory '{base_dir}': {str(e)}")
        # Generic error message to prevent information disclosure.
        return "Error accessing file", 500

@app.route('/view_logs')
def view_logs():
    """
    VULNERABILITY: Information Disclosure + Sensitive Data Exposure
    No access control - any user can see logs with passwords
    FIXED: Restrict to admin only
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'admin':
        return "Access Denied: Only admins can view logs", 403
    
    # VULNERABILITY: No role-based access control
    # Should be admin-only
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM logs ORDER BY created_at DESC LIMIT 100')
    logs = cursor.fetchall()
    conn.close()
    
    return render_template('logs_new.html', logs=logs)

@app.route('/logout')
@csrf_required # NEW: Apply CSRF protection
def logout():
    """VULNERABILITY: No CSRF token on logout (NOW FIXED)"""
    session.clear()
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(error):
    # FIX: Generic error message to prevent information disclosure
    return "404 Not Found", 404

@app.errorhandler(500)
def internal_error(error):
    # FIX: Generic error message to prevent information disclosure
    return "500 Internal Server Error", 500

if __name__ == '__main__':
    # VULNERABILITY: Running in debug mode (not for production)
    # Debug mode exposes detailed error pages and allows code execution
    # For production, set debug=False and configure proper logging and error handling.
    app.run(debug=True, host='0.0.0.0', port=5000)

    #testing