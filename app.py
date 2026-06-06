# Main Flask Application - Secure Student Management System
from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file, current_app, send_from_directory
from werkzeug.utils import secure_filename, generate_password_hash, check_password_hash # Added for password handling
from markupsafe import escape # Added for XSS fix
from flask_wtf.csrf import CSRFProtect, CSRFError # Added for CSRF protection
import os
import database
from config import Config
from datetime import datetime, timedelta
import uuid # For unique filenames

app = Flask(__name__)
app.config.from_object(Config)

# Configure Flask-CSRF
csrf = CSRFProtect(app)

# Ensure session is secure
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Or 'Strict' depending on requirements
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Enforce session timeout

# SECURE: Override or set a robust UPLOAD_FOLDER and STATIC_ASSETS_FOLDER.
# The default UPLOAD_FOLDER from Config might be a relative path or even '.' which is risky.
# We ensure it's an absolute path, ideally outside the application's source tree.
# For this example, we place user uploads in Flask's instance_path, which is designed for app-specific data
# that shouldn't be in version control, making it a safer default than app.root_path.
# In a production environment, this should ideally be configured to a known, non-web-accessible path like '/var/app_data/my_app_uploads'.
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'user_uploads')

# Define a separate, dedicated folder for application-provided public static assets.
# This prevents mixing user uploads with application's static content and isolates it from sensitive source code.
app.config['STATIC_ASSETS_FOLDER'] = os.path.join(app.root_path, 'application_static_public')

# Initialize database
if not os.path.exists(database.DB_NAME):
    database.init_db()

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# Ensure static assets folder exists
os.makedirs(app.config['STATIC_ASSETS_FOLDER'], exist_ok=True)

# SECURE: Rate limiting for login attempts
# Stores {username: [timestamp1, timestamp2, ...]}
LOGIN_ATTEMPTS = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = timedelta(minutes=15)
ATTEMPT_WINDOW = timedelta(minutes=5)

def record_login_attempt(username):
    """Records a login attempt and cleans up old attempts."""
    now = datetime.now()
    if username not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[username] = []
    
    # Clean up attempts older than ATTEMPT_WINDOW
    LOGIN_ATTEMPTS[username] = [ts for ts in LOGIN_ATTEMPTS[username] if now - ts < ATTEMPT_WINDOW]
    LOGIN_ATTEMPTS[username].append(now)

def check_rate_limit(username):
    """Checks if a user is rate-limited or locked out."""
    now = datetime.now()
    if username in LOGIN_ATTEMPTS:
        attempts_in_window = [ts for ts in LOGIN_ATTEMPTS[username] if now - ts < ATTEMPT_WINDOW]
        
        # If max attempts exceeded within the window, check if lockout time has passed
        if len(attempts_in_window) >= MAX_LOGIN_ATTEMPTS:
            # The earliest recorded attempt within the current lockout window
            earliest_attempt_time = LOGIN_ATTEMPTS[username][0]
            if now - earliest_attempt_time < LOCKOUT_TIME:
                return False # Locked out
    return True

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = app.config['PERMANENT_SESSION_LIFETIME']

@app.route('/')
def index():
    """Home page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return f"<h1>Welcome to Secure Student Management System</h1><a href='/logout'>Logout</a><br><a href='/dashboard'>Dashboard</a>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    SECURE: Addresses multiple security flaws.
    1. SQL Injection in authentication (FIXED in database.py).
    2. Rate limiting for Brute Force/Credential Stuffing.
    3. Weak password handling (FIXED with hashing in database.py and here).
    4. CSRF protection (via Flask-CSRF).
    5. Sensitive error messages (generic messages).
    6. Session timeout enforcement.
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # SECURE: Input validation for username/password length/characters
        if not username or not password:
            flash("Username and password cannot be empty.", 'danger')
            database.log_action('LOGIN_FAILED', username, "Missing credentials")
            return render_template('login_new.html')

        # SECURE: Rate limiting check
        if not check_rate_limit(username):
            flash("Too many failed login attempts. Please try again later.", 'danger')
            database.log_action('LOGIN_FAILED', username, "Rate limit exceeded")
            return render_template('login_new.html')
        
        # SECURE: Record login attempt before authentication to prevent timing attacks
        record_login_attempt(username)

        # SECURE: Authenticate user using hashed passwords
        user = database.authenticate_user(username, password) # database.authenticate_user now checks hashed passwords
        
        if user:
            # Clear attempts on successful login
            if username in LOGIN_ATTEMPTS:
                del LOGIN_ATTEMPTS[username]

            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email'] = user[3]
            session['role'] = user[4]
            # session.permanent is set globally via @app.before_request
            
            database.log_action('LOGIN_SUCCESS', username, f"User logged in successfully from IP: {request.remote_addr}")
            
            flash("Login successful!", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", 'danger') # Generic error message
            database.log_action('LOGIN_FAILED', username, f"Failed login attempt from IP: {request.remote_addr}") # Password removed from log
            return render_template('login_new.html')
    
    return render_template('login_new.html')

@app.route('/dashboard')
def dashboard():
    """
    SECURE: Role-based dashboard access.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        # Students should go to their profile page, not general dashboard
        return redirect(url_for('student_profile'))

    return render_template('dashboard_new.html')

@app.route('/students')
def students():
    """
    SECURE: Access control enforced, sensitive data (SSN, passwords) not exposed.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        flash("Access Denied: Students cannot view all student records", 'danger')
        return redirect(url_for('dashboard')) # Redirect to dashboard or student_profile
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    # SECURE: Do NOT select SSN or password
    cursor.execute('SELECT id, roll_no, name, email, phone FROM students')
    students_list = cursor.fetchall()
    conn.close()
    
    return render_template('students_new.html', students=students_list)

@app.route('/student/<int:student_id>') # Use <int:student_id> for type validation
def view_student(student_id):
    """
    SECURE: SQL Injection prevented (via database.py), sensitive data (SSN, password) not exposed.
    Access restricted based on role.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        # If student tries to view another student's record
        flash("Access Denied: Students cannot view other student records", 'danger')
        return redirect(url_for('student_profile')) # Redirect to their own profile
    
    # SECURE: database.get_student_details now returns safe data (no SSN/password)
    student = database.get_student_details(student_id)
    
    if not student:
        flash("Student not found", 'danger')
        return redirect(url_for('students')) # Redirect back to student list or dashboard
    
    return render_template('student_view.html', student=student)

@app.route('/student/profile')
def student_profile():
    """
    SECURE: Student can view only their own profile.
    Restricts access based on email matching between user and student record.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'student':
        flash("Access Denied: Only students can view their profile", 'danger')
        return redirect(url_for('dashboard'))
    
    user_email = session.get('email')
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT id, roll_no, name, email, phone, address, gpa FROM students WHERE email = ?', (user_email,))
    student = cursor.fetchone()
    conn.close()
    
    if not student:
        flash("Your student record not found", 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('student_profile_new.html', student=student)

@app.route('/student/grades')
def student_grades():
    """
    SECURE: Student can view only their own grades and GPA.
    Restricts access to student role only.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'student':
        flash("Access Denied: Only students can view their grades", 'danger')
        return redirect(url_for('dashboard'))
    
    user_email = session.get('email')
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT roll_no, name, gpa FROM students WHERE email = ?', (user_email,))
    student = cursor.fetchone()
    conn.close()
    
    if not student:
        flash("Your student record not found", 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('student_grades_new.html', student=student)

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    """
    SECURE: Implements input validation, SQL Injection prevention (via database.py),
            privilege check, and password hashing.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'admin':
        flash("Access Denied: Only admins can add students", 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        roll_no = request.form.get('roll_no', '').strip()
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        ssn = request.form.get('ssn', '').strip()
        gpa_str = request.form.get('gpa', '0').strip()
        
        # SECURE: Input validation and sanitization
        errors = []
        if not (roll_no and name and email and phone and address and ssn):
            errors.append("All fields except GPA are required.")
        if not roll_no.isalnum() or len(roll_no) > 10: # Example validation
            errors.append("Roll number must be alphanumeric and max 10 chars.")
        if not name.replace(' ', '').isalpha():
            errors.append("Name must contain only alphabetic characters and spaces.")
        if not "@" in email or "." not in email: # Basic email validation
            errors.append("Invalid email format.")
        if not phone.isdigit() or len(phone) < 10 or len(phone) > 15:
            errors.append("Phone number must be digits only and 10-15 characters long.")
        if not (len(ssn) == 11 and ssn[3] == '-' and ssn[6] == '-' and ssn.replace('-', '').isdigit()):
            errors.append("SSN must be in XXX-XX-XXXX format.")
        
        try:
            gpa = float(gpa_str)
            if not (0.0 <= gpa <= 4.0):
                errors.append("GPA must be between 0.0 and 4.0.")
        except ValueError:
            errors.append("GPA must be a valid number.")

        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('add_student_new.html', form_data=request.form) # Repopulate form with invalid data

        # SECURE: Hash the student's password (e.g., using roll_no as initial password)
        initial_password_hash = generate_password_hash(roll_no) # Consider a more secure initial password policy

        if database.add_student(roll_no, name, email, phone, address, ssn, gpa, initial_password_hash):
            flash('Student added successfully!', 'success')
            database.log_action('ADD_STUDENT', session.get('username'), f"Added student {name} (Roll: {roll_no})")
            return redirect(url_for('dashboard'))
        else:
            flash('Error adding student. Roll number or email might already exist.', 'danger')
            database.log_action('ADD_STUDENT_FAILED', session.get('username'), f"Failed to add student {name} (Roll: {roll_no})")
            return render_template('add_student_new.html', form_data=request.form)
    
    return render_template('add_student_new.html')

@app.route('/search', methods=['GET', 'POST'])
def search_students():
    """
    SECURE: SQL Injection prevented (via database.py), XSS prevented (output encoding),
            access control enforced.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        flash("Access Denied: Students cannot search student records", 'danger')
        return redirect(url_for('dashboard'))
    
    results = []
    search_term = '' # Initialize search_term
    if request.method == 'POST':
        search_term = request.form.get('search', '').strip()
        
        # SECURE: SQL Injection already handled by database.py using parameterized queries
        results = database.search_students(search_term)
        
        # SECURE: Log search terms without revealing sensitive internal details
        database.log_action('SEARCH_STUDENTS', session.get('username'), f"Search performed for: {search_term}")
    
    # SECURE: Pass the HTML-escaped search term to the template.
    # Jinja2 auto-escapes by default, but explicitly escaping here acts as a defense-in-depth,
    # ensuring the search term is always safe for HTML context, even if template auto-escaping is
    # accidentally disabled or bypassed with '|safe'.
    return render_template('search_new.html', results=results, search_term_reflected=escape(search_term))

# Whitelist allowed extensions for uploads
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """
    SECURE: Implements file type validation, uses secure filenames,
            prevents path traversal, enforces file size limits, and access control.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role == 'student':
        flash("Access Denied: Only admin and users can upload files", 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('upload_file'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('upload_file'))
        
        # SECURE: File type validation (whitelist)
        if not allowed_file(file.filename):
            flash('Invalid file type. Only txt, pdf, png, jpg, jpeg, gif, doc, docx are allowed.', 'danger')
            database.log_action('FILE_UPLOAD_FAILED', session.get('username'), f"Attempted upload with disallowed extension: {file.filename}")
            return redirect(url_for('upload_file'))

        # SECURE: File size limit (e.g., 5 MB)
        if 'CONTENT_LENGTH' in request.headers and int(request.headers['CONTENT_LENGTH']) > 5 * 1024 * 1024: # 5MB limit
            flash('File size exceeds the limit of 5MB.', 'danger')
            database.log_action('FILE_UPLOAD_FAILED', session.get('username'), f"Attempted upload exceeding size limit: {file.filename}")
            return redirect(url_for('upload_file'))
        
        # SECURE: Use secure_filename to prevent path traversal
        filename = secure_filename(file.filename)
        
        # SECURE: Generate a unique filename to prevent collisions and overwrite attacks
        unique_filename = str(uuid.uuid4()) + "_" + filename
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            file.save(filepath)
            database.log_action('FILE_UPLOAD', session.get('username'), f"Uploaded file: {unique_filename}")
            flash(f'File "{filename}" uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error uploading file: {str(e)}', 'danger')
            database.log_action('FILE_UPLOAD_FAILED', session.get('username'), f"Error saving file {filename}: {str(e)}")
            return redirect(url_for('upload_file'))
    
    return render_template('upload_new.html')

@app.route('/download/<filename>') # Original route
def download_file(filename):
    """
    SECURE: Prevents Path Traversal by using send_from_directory.
    This route serves user-uploaded files from a dedicated, secure UPLOAD_FOLDER.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # SECURE: send_from_directory ensures file is within the base directory and sanitizes filename.
        # It handles path traversal attempts automatically. This now points to the securely defined app.config['UPLOAD_FOLDER'].
        database.log_action('FILE_DOWNLOAD', session.get('username'), f"Attempted download of uploaded file: {filename}")
        return send_from_directory(app.config['UPLOAD_FOLDER'], secure_filename(filename), as_attachment=True)
    except FileNotFoundError:
        flash("File not found or access denied.", 'danger')
        database.log_action('FILE_DOWNLOAD_FAILED', session.get('username'), f"Uploaded file not found: {filename}")
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", 'danger')
        database.log_action('FILE_DOWNLOAD_FAILED', session.get('username'), f"Error downloading uploaded file {filename}: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/static_assets/<path:filepath>') # Renamed endpoint to be more specific and restrict to known safe assets
def access_file(filepath):
    """
    SECURE: Restricted file access to a specific, safe directory using send_from_directory.
    This endpoint is now dedicated to serving application-provided static content, not user uploads.
    """
    if 'user_id' not in session: # Still require auth for this example, could be public for true static assets
        return redirect(url_for('login'))
    
    try:
        # SECURE: Use send_from_directory to serve files ONLY from the new designated STATIC_ASSETS_FOLDER.
        # This prevents access to arbitrary files on the system via path traversal and isolates static assets
        # from user uploads and application source code. It also implicitly handles path validation.
        safe_directory = app.config['STATIC_ASSETS_FOLDER']
        
        # Verify the file is actually intended to be served as a static asset.
        # This check is a defense-in-depth, as send_from_directory itself should prevent traversal.
        full_path = os.path.join(safe_directory, filepath)
        if not os.path.exists(full_path) or not os.path.isfile(full_path):
             raise FileNotFoundError # Ensure it's a file and exists within the designated static directory

        database.log_action('FILE_ACCESS', session.get('username'), f"Accessed static asset: {filepath}")
        return send_from_directory(safe_directory, filepath)

    except FileNotFoundError:
        flash("Static asset not found or access denied.", 'danger')
        database.log_action('FILE_ACCESS_FAILED', session.get('username'), f"Static asset not found: {filepath}")
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f"Error accessing static asset: {str(e)}", 'danger')
        database.log_action('FILE_ACCESS_FAILED', session.get('username'), f"Error accessing static asset {filepath}: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/view_logs')
def view_logs():
    """
    SECURE: Information Disclosure minimized by not logging sensitive details.
    Access control for admin only is enforced.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    if role != 'admin':
        flash("Access Denied: Only admins can view logs", 'danger')
        return redirect(url_for('dashboard'))
    
    conn = database.sqlite3.connect(database.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT created_at, username, action, details FROM logs ORDER BY created_at DESC LIMIT 100')
    logs = cursor.fetchall()
    conn.close()
    
    return render_template('logs_new.html', logs=logs)

@app.route('/logout', methods=['POST']) # SECURE: Logout with POST to prevent CSRF
def logout():
    """SECURE: Logout protected with CSRF token."""
    session.clear()
    flash("You have been logged out.", 'info')
    database.log_action('LOGOUT', session.get('username', 'anonymous'), "User logged out")
    return redirect(url_for('login'))

@app.errorhandler(400)
def bad_request(error):
    # SECURE: Generic error message
    flash("Bad Request: The server could not understand your request.", 'danger')
    current_app.logger.warning(f"Bad Request (400): {request.url} - {error}")
    return render_template('error.html', error_code=400, error_message="Bad Request"), 400

@app.errorhandler(403)
def forbidden(error):
    # SECURE: Generic error message
    flash("Forbidden: You do not have permission to access this resource.", 'danger')
    current_app.logger.warning(f"Forbidden (403): {request.url} - {session.get('username', 'anonymous')} - {error}")
    return render_template('error.html', error_code=403, error_message="Forbidden"), 403

@app.errorhandler(404)
def not_found(error):
    # SECURE: Generic error message
    flash("Page Not Found: The requested URL was not found on the server.", 'danger')
    current_app.logger.warning(f"Not Found (404): {request.url} - {error}")
    return render_template('error.html', error_code=404, error_message="Page Not Found"), 404

@app.errorhandler(405)
def method_not_allowed(error):
    flash("Method Not Allowed: The method is not allowed for the requested URL.", 'danger')
    current_app.logger.warning(f"Method Not Allowed (405): {request.method} {request.url} - {error}")
    return render_template('error.html', error_code=405, error_message="Method Not Allowed"), 405

@app.errorhandler(500)
def internal_error(error):
    # SECURE: Generic error message, avoid exposing stack trace in production
    current_app.logger.error(f"Server Error: {error}", exc_info=True) # Log full error for internal review
    flash("Internal Server Error: Something went wrong on our end. Please try again later.", 'danger')
    return render_template('error.html', error_code=500, error_message="Internal Server Error"), 500

if __name__ == '__main__':
    # SECURE: Do NOT run in debug mode for production
    app.run(debug=False, host='0.0.0.0', port=5000)
