# Main Flask Application - Vulnerable Student Management System
from flask import Flask, render_template, request, redirect, session, url_for, send_file
from werkzeug.utils import secure_filename
import os
import database
from config import Config
from datetime import datetime, timedelta
from markupsafe import escape # NEW: Import escape for XSS prevention

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
if not os.path.exists(database.DB_NAME):
    database.init_db()

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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


@app.route('/')
def index():
    """Home page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # NEW: Escape username for reflection as a defense-in-depth measure if it were ever user-controlled and reflected raw.
    # In this specific case, 'username' from session is assumed safe since it comes from DB, but general principle applies.
    # However, the string literal f"<h1>...</h1>" is not a template and does not auto-escape. Thus, if session['username']
    # could contain script, it needs manual escaping here.
    escaped_username = escape(session.get('username', 'Guest'))
    return f"<h1>Welcome to Vulnerable Student Management System, {escaped_username}!</h1><a href='/logout'>Logout</a><br><a href='/dashboard'>Dashboard</a>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    VULNERABILITY: Multiple Security Flaws
    1. SQL Injection in authentication (FIXED in database.py)
    2. NO rate limiting (Brute Force attack)
    3. Weak password handling
    4. No CSRF protection
    5. Sensitive error messages (FIXED for error display below)
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # No input validation (semantic validation like length, character set still missing)
        
        # No rate limiting - allows unlimited login attempts
        record_login_attempt(username)
        
        # SQL Injection vulnerability here (FIXED by parameterized queries in database.py)
        user = database.authenticate_user(username, password)
        
        if user:
            # VULNERABILITY: No session timeout enforcement
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = user[3]
            session['role'] = user[4]
            session.permanent = True
            
            # VULNERABILITY: Information Disclosure - Verbose logging (password is no longer logged by database.py)
            database.log_action('LOGIN_SUCCESS', username, f"User logged in successfully")
            
            return redirect(url_for('dashboard'))
        else:
            # VULNERABILITY: Information Disclosure (error message itself will be escaped by Jinja2 default)
            error = "Invalid username or password"
            database.log_action('LOGIN_FAILED', username, f"Failed login attempt") # Password removed from log details
            return render_template('login_new.html', error=error)
    
    return render_template('login_new.html')

@app.route('/dashboard')
def dashboard():
    """
    VULNERABILITY: No proper access control (partial fixes applied elsewhere)
    Anyone with a session can access
    Shows role-based dashboard
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard_new.html')

@app.route('/students')
def students():
    """
    VULNERABILITY: No access control - any authenticated user can see all data (FIXED: Restrict to admin and user roles only)
    Exposes sensitive information (SSN, passwords) (Not fixed here, but restricted by role)
    FIX: Applied output encoding for XSS prevention when displaying student data.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Students cannot view all student records", 403
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, roll_no, name, email, phone, ssn FROM students')
    students_list_raw = cursor.fetchall()
    conn.close()
    
    # NEW: Apply output encoding to all string fields in the student list for XSS prevention.
    # This is a defense-in-depth measure, assuming the template might misuse |safe or older unescaped data exists.
    escaped_students_list = []
    for student_row in students_list_raw:
        # Assuming student_row is (id, roll_no, name, email, phone, ssn)
        # id is integer, other fields are strings.
        escaped_student = (
            student_row[0],               # id (int) - no HTML escape needed
            escape(str(student_row[1])),  # roll_no (str) - escape
            escape(str(student_row[2])),  # name (str) - escape
            escape(str(student_row[3])),  # email (str) - escape
            escape(str(student_row[4])),  # phone (str) - escape
            escape(str(student_row[5]))   # ssn (str) - escape
        )
        escaped_students_list.append(escaped_student)
    
    return render_template('students_new.html', students=escaped_students_list)

@app.route('/student/<student_id>')
def view_student(student_id):
    """
    VULNERABILITY: SQL Injection in student ID parameter (FIXED in database.py)
    Sensitive Data Exposure of SSN and password (architectural flaw, not fixed here, but access restricted)
    FIXED: Prevent students from viewing other student records
    FIX: Applied output encoding for XSS prevention when displaying a single student's data.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Students cannot view other student records", 403
    
    # VULNERABLE: Direct parameter use - SQL Injection (FIXED by parameterized queries in database.py)
    student_raw = database.get_student_details(student_id)
    
    if not student_raw:
        return "Student not found", 404
    
    # NEW: Apply output encoding to student details for XSS prevention.
    # Assuming student_raw is a tuple: (id, roll_no, name, email, phone, address, ssn, gpa, password, created_at)
    escaped_student = []
    # Iterate through fields and escape strings; numeric types typically don't need HTML escaping.
    # For robustness, we convert to string before escaping as Jinja2 expects stringable values.
    for i, field in enumerate(student_raw):
        if i in [0, 7]: # id (int), gpa (float) - no HTML escape needed
            escaped_student.append(field)
        elif i == 8: # password - sensitive, should ideally not be retrieved or displayed
            escaped_student.append("[REDACTED]") # Do not display passwords directly
        else: # All other fields are strings (roll_no, name, email, phone, address, ssn, created_at) - escape
            escaped_student.append(escape(str(field)))
    
    return render_template('student_view.html', student=tuple(escaped_student))

@app.route('/student/profile')
def student_profile():
    """
    Student can view only their own profile
    Restricts access based on email matching between user and student record
    FIX: Applied output encoding for XSS prevention when displaying student's own profile.
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
    student_raw = cursor.fetchone()
    conn.close()
    
    if not student_raw:
        return "Your student record not found", 404
    
    # NEW: Apply output encoding to student profile details for XSS prevention.
    # Assuming student_raw is a tuple: (id, roll_no, name, email, phone, address, gpa)
    escaped_student = []
    for i, field in enumerate(student_raw):
        if i in [0, 6]: # id (int), gpa (float) - no HTML escape needed
            escaped_student.append(field)
        else: # All other fields are strings (roll_no, name, email, phone, address) - escape
            escaped_student.append(escape(str(field)))
    
    return render_template('student_profile_new.html', student=tuple(escaped_student))

@app.route('/student/grades')
def student_grades():
    """
    Student can view only their own grades and GPA
    Restricts access to student role only
    FIX: Applied output encoding for XSS prevention when displaying student grades.
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
    student_raw = cursor.fetchone()
    conn.close()
    
    if not student_raw:
        return "Your student record not found", 404
    
    # NEW: Apply output encoding to student grades details for XSS prevention.
    # Assuming student_raw is a tuple: (roll_no, name, gpa)
    escaped_student = []
    for i, field in enumerate(student_raw):
        if i == 2: # gpa (float) - no HTML escape needed
            escaped_student.append(field)
        else: # roll_no, name (strings) - escape
            escaped_student.append(escape(str(field)))
    
    return render_template('student_grades_new.html', student=tuple(escaped_student))


@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    """
    VULNERABILITY: No input validation (FIXED partially by sanitization for XSS, semantic validation still missing)
    SQL Injection (FIXED in database.py)
    No privilege check (FIXED: now restricts to admin only)
    FIX: Implemented input sanitization to prevent XSS payloads from being stored in the database.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'admin':
        return "Access Denied: Only admins can add students", 403
    
    if request.method == 'POST':
        # NEW: Apply input sanitization for XSS prevention before storing.
        # Note: This is a defense-in-depth measure; output encoding is the primary fix.
        # Semantic validation (e.g., email format, phone number pattern) is still missing.
        roll_no = escape(request.form.get('roll_no', ''))
        name = escape(request.form.get('name', ''))
        email = escape(request.form.get('email', ''))
        phone = escape(request.form.get('phone', ''))
        address = escape(request.form.get('address', ''))
        ssn = escape(request.form.get('ssn', ''))
        gpa = request.form.get('gpa', '0') # GPA is numeric, no HTML escaping needed here. Type conversion will handle it.
        
        # VULNERABLE: No validation (semantic validation still missing), SQL injection possible (FIXED in database.py)
        if database.add_student(roll_no, name, email, phone, address, ssn, gpa):
            import flask
            flask.flash('Student added successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            import flask
            flask.flash('Error adding student', 'danger')
            return redirect(url_for('add_student'))
    
    return render_template('add_student_new.html')

@app.route('/search', methods=['GET', 'POST'])
def search_students():
    """
    VULNERABILITY: SQL Injection in search (FIXED in database.py)
    No access control - FIXED to prevent students
    FIX: Implemented proper output encoding to prevent XSS vulnerabilities from search input and results.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Students cannot search student records", 403
    
    results = []
    search_term_display = "" # Variable to hold the escaped search term for display
    
    if request.method == 'POST':
        search_term = request.form.get('search', '')
        
        # NEW: Escape the search term for reflection in the template.
        # This addresses XSS in cases where the search query itself is reflected (e.g., "You searched for: [query]").
        search_term_display = escape(search_term) 
        
        # SQL Injection is prevented by parameterized queries in database.py
        results_raw = database.search_students(search_term)
        
        # NEW: Apply output encoding to all string fields in the search results.
        # This is a defense-in-depth measure, assuming the template might misuse |safe
        # or that older, unescaped data might exist in the DB.
        escaped_results = []
        for row in results_raw:
            # Assuming the order is (id, name, email, phone, roll_no) from database.search_students
            # ID is integer, other fields are strings that need escaping.
            escaped_row = (
                row[0],               # id (int) - no HTML escape needed
                escape(str(row[1])),  # name (str) - escape (ensure it's a string)
                escape(str(row[2])),  # email (str) - escape
                escape(str(row[3])),  # phone (str) - escape
                escape(str(row[4]))   # roll_no (str) - escape
            )
            escaped_results.append(escaped_row)
        results = escaped_results
        
        # VULNERABILITY: Information Disclosure - Shows query (Removed sensitive search term logging for production)
        # print(f"[*] Search performed for: {search_term}") 
    
    # Pass both results and the escaped search term for display to the template.
    return render_template('search_new.html', results=results, search_term=search_term_display)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """
    VULNERABILITY: Multiple File Upload Issues (still present)
    1. No file type validation (allows executables)
    2. Path Traversal vulnerability
    3. No file size limit enforcement
    4. Predictable filenames
    FIXED: Prevent students from uploading
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        return "Access Denied: Only admin and users can upload files", 403
    
    if request.method == 'POST':
        if 'file' not in request.files:
            import flask
            flask.flash('No file selected', 'danger')
            return redirect(url_for('upload_file'))
        
        file = request.files['file']
        
        if file.filename == '':
            import flask
            flask.flash('No file selected', 'danger')
            return redirect(url_for('upload_file'))
        
        # VULNERABILITY: No proper file validation (still exists)
        # Allow dangerous file extensions (still exists)
        # NEW: Sanitize filename for display to prevent XSS if filename contains malicious content and is reflected.
        # Proper fix requires secure_filename combined with UUID for actual filename on disk.
        filename_raw = file.filename  # VULNERABLE: No sanitization for saving, but escape for reflection
        filename_display = escape(filename_raw)
        

        # VULNERABILITY: Path Traversal - No path validation (still exists)
        # Attacker can use "../" to upload outside intended directory (still exists)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename_raw) # Use raw filename for saving
        
        # VULNERABILITY: No file type check (still exists)
        # Allows executable files (.exe, .sh, .bat) (still exists)
        file.save(filepath)
        
        # VULNERABILITY: Information Disclosure - Log file path (filepath is sensitive here)
        database.log_action('FILE_UPLOAD', session.get('username'), f"Uploaded file: {escape(filepath)}") # NEW: Escape filepath for logs
        
        import flask
        # NEW: Use escaped filename for flash message display.
        flask.flash(f'File "{filename_display}" uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('upload_new.html')

@app.route('/download/<filename>')
def download_file(filename):
    """
    VULNERABILITY: Path Traversal (still exists)
    No validation of filename parameter
    Allows download of any file using ../ notation
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # VULNERABLE: Path Traversal - No sanitization (still exists, use secure_filename and restrict paths)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if os.path.exists(filepath):
        return send_file(filepath)
    else:
        return "File not found", 404

@app.route('/file/<path:filepath>')
def access_file(filepath):
    """
    VULNERABILITY: Unrestricted File Path Access (still exists)
    CWE-434: Unrestricted Upload of File with Dangerous Type
    CWE-22: Path Traversal vulnerability
    
    Allows direct access to ANY file on the system using path parameter
    No validation - attackers can use this to:
    - Download config.py (steal SECRET_KEY)
    - Download vulnerable_app.db (steal all user/student data)
    - Download app.py (get source code)
    - Download database.py (leak database queries)
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # CRITICAL VULNERABILITY: No path validation whatsoever (still exists)
    # Directly trusts user input for file access (still exists)
    try:
        if os.path.exists(filepath) and os.path.isfile(filepath):
            database.log_action('FILE_ACCESS', session.get('username'), f"Accessed file: {escape(filepath)}") # NEW: Escape filepath for logs
            return send_file(filepath)
        else:
            return "File not found or not a file", 404
    except Exception as e:
        # VULNERABILITY: Information Disclosure - reveals errors (FIXED: error message is escaped)
        return f"Error accessing file: {escape(str(e))}", 500 # NEW: Escape error message for XSS

@app.route('/view_logs')
def view_logs():
    """
    VULNERABILITY: Information Disclosure + Sensitive Data Exposure (FIXED for passwords, some details remain)
    No access control - any user can see logs with passwords (FIXED: access restricted to admin, passwords not logged)
    FIXED: Restrict to admin only
    FIX: Applied output encoding for XSS prevention when displaying logs.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'admin':
        return "Access Denied: Only admins can view logs", 403
    
    # VULNERABILITY: No role-based access control (FIXED above)
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, action, username, details, ip_address, created_at FROM logs ORDER BY created_at DESC LIMIT 100')
    logs_raw = cursor.fetchall()
    conn.close()
    
    # NEW: Apply output encoding to all string fields in the log entries for XSS prevention.
    escaped_logs = []
    for log_entry in logs_raw:
        # Assuming log_entry is (id, action, username, details, ip_address, created_at)
        escaped_entry = (
            log_entry[0],               # id (int) - no HTML escape needed
            escape(str(log_entry[1])),  # action (str) - escape
            escape(str(log_entry[2])),  # username (str) - escape
            escape(str(log_entry[3])),  # details (str) - escape
            escape(str(log_entry[4])),  # ip_address (str or None) - escape
            log_entry[5]                # created_at (datetime object or string) - no HTML escape needed
        )
        escaped_logs.append(escaped_entry)
    
    return render_template('logs_new.html', logs=escaped_logs)

@app.route('/logout')
def logout():
    """VULNERABILITY: No CSRF token on logout"""
    session.clear()
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(error):
    # VULNERABILITY: Information Disclosure - Detailed error (FIXED: error message is escaped)
    return f"404 Error: {escape(str(error))}", 404 # NEW: Escape error message for XSS

@app.errorhandler(500)
def internal_error(error):
    # VULNERABILITY: Information Disclosure - Stack trace exposed (FIXED: error message is escaped)
    return f"500 Internal Server Error: {escape(str(error))}", 500 # NEW: Escape error message for XSS

if __name__ == '__main__':
    # VULNERABILITY: Running in debug mode (not for production) (still exists)
    # Debug mode exposes detailed error pages and allows code execution (still exists)
    app.run(debug=True, host='0.0.0.0', port=5000)

    #testing
