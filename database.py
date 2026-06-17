# Database Module - Contains SQL Injection Vulnerabilities (FIXED)
import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash # Added for secure password handling

DB_NAME = 'vulnerable_app.db'

def init_db():
    """Initialize the database with secure schema and hashed passwords"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, -- Storing hashed passwords
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create students table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_no TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            ssn TEXT NOT NULL, -- Sensitive, consider encrypting or further restricting access
            gpa REAL,
            password TEXT, -- Storing hashed student passwords (e.g., for self-service portal, though users table is preferred)
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create logs table - VULNERABLE: Logs sensitive data (Information Disclosure) - Addressed in app.py by not sending sensitive data to logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            username TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default admin user with strong credentials (hashed)
    cursor.execute('DELETE FROM users')  # Clean slate
    cursor.execute('DELETE FROM students') # Clean slate for students too
    
    # Hashed passwords for default users
    admin_password = generate_password_hash('admin123!Strong') # Using stronger default passwords
    user_password = generate_password_hash('userpassword!Secure')
    john_password = generate_password_hash('student123!Secure')
    sarah_password = generate_password_hash('student456!Secure')

    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('admin', admin_password, 'admin@university.edu', 'admin'))
    
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('user', user_password, 'user@university.edu', 'user'))
    
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('john_student', john_password, 'john.student@university.edu', 'student'))
    
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('sarah_student', sarah_password, 'sarah.student@university.edu', 'student'))
    
    # Add student records that correspond to student logins
    cursor.execute('''
        INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('10001', 'John Smith', 'john.student@university.edu', '9876543210', '123 Main St', '123-45-6789', 3.85, john_password))
    
    cursor.execute('''
        INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('10002', 'Sarah Johnson', 'sarah.student@university.edu', '9876543211', '456 Oak Ave', '987-65-4321', 3.92, sarah_password))
    
    cursor.execute('''
        INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('10003', 'Michael Brown', 'michael@university.edu', '9876543212', '789 Pine Rd', '456-78-9012', 3.45, generate_password_hash('pass123!Secure')))
    
    conn.commit()
    conn.close()
    print("[*] Database initialized successfully")

def authenticate_user(username, password):
    """
    SECURE: Authenticates a user using hashed passwords and parameterized queries.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    user = None
    try:
        # Retrieve user by username
        cursor.execute("SELECT id, username, password, email, role FROM users WHERE username = ?", (username,))
        stored_user = cursor.fetchone()
        
        if stored_user and check_password_hash(stored_user[2], password): # Check hashed password
            user = stored_user
            log_action('AUTH_ATTEMPT', username, f"Result: Success")
        else:
            log_action('AUTH_ATTEMPT', username, f"Result: Failed") # Removed password from log
    except Exception as e:
        print(f"[ERROR] Database operation failed during authentication: {str(e)}")
        log_action('AUTH_ATTEMPT', username, f"Result: Error - {str(e)}")
    finally:
        conn.close()
    
    return user

def search_students(search_term):
    """
    SECURE: Searches for students securely using parameterized queries.
    Removes sensitive data (SSN, password) from search results.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    search_term_like = f"%{search_term}%"
    # Do not return SSN or password in search results
    query = "SELECT id, name, email, phone, roll_no FROM students WHERE name LIKE ? OR roll_no LIKE ? OR email LIKE ?"
    
    try:
        cursor.execute(query, (search_term_like, search_term_like, search_term_like))
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        print(f"[ERROR] Secure search failed: {str(e)}")
        log_action('SEARCH_FAILED', 'system', f"Search term: {search_term} - Error: {str(e)}")
        return []

def get_student_details(student_id):
    """
    SECURE: Retrieves student details securely, excluding sensitive fields (SSN, password)
            unless explicitly required and access-controlled.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Do not select SSN or password by default for general viewing.
    # If SSN is needed, it should be in a separate, highly privileged function.
    query = "SELECT id, roll_no, name, email, phone, address, gpa FROM students WHERE id = ?"
    
    try:
        cursor.execute(query, (student_id,))
        student = cursor.fetchone()
        conn.close()
        return student
    except Exception as e:
        print(f"[ERROR] Secure query for student details failed: {str(e)}")
        log_action('STUDENT_DETAILS_FAILED', 'system', f"Student ID: {student_id} - Error: {str(e)}")
        return None

def add_student(roll_no, name, email, phone, address, ssn, gpa, password_hash):
    """
    SECURE: Adds a student with a hashed password using parameterized queries.
            Assumes password_hash is pre-hashed by the calling function.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        query = '''
            INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        # password_hash is expected to be already hashed
        cursor.execute(query, (roll_no, name, email, phone, address, ssn, gpa, password_hash))
        conn.commit()
        conn.close()
        log_action('ADD_STUDENT_SUCCESS', 'system', f"Added student: {roll_no} - {name}")
        return True
    except sqlite3.IntegrityError:
        print(f"[ERROR] Failed to add student: Duplicate roll number or email.")
        log_action('ADD_STUDENT_FAILED', 'system', f"Duplicate entry for student: {roll_no} - {name}")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to securely add student: {str(e)}")
        log_action('ADD_STUDENT_FAILED', 'system', f"Error adding student: {roll_no} - {name} - Error: {str(e)}")
        return False

def log_action(action, username, details):
    """
    SECURE: Logs actions. Avoids logging sensitive data by ensuring 'details' is sanitized before calling.
    """
    try:
        conn = sqlite3.connect(DB_NAME, timeout=5.0)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO logs (action, username, details) 
            VALUES (?, ?, ?)
        ''', (action, username, details))
        
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        print(f"[WARNING] Could not log action (database locked): {str(e)}")
    except Exception as e:
        print(f"[ERROR] Failed to log action: {str(e)}")