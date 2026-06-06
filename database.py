# Database Module - Contains SQL Injection Vulnerabilities (FIXED)
import sqlite3
import os
from datetime import datetime

DB_NAME = 'vulnerable_app.db'

def init_db():
    """Initialize the database with vulnerable schema"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
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
            ssn TEXT NOT NULL,
            gpa REAL,
            password TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create logs table - VULNERABLE: Logs sensitive data (Information Disclosure)
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
    
    # Insert default admin user with weak credentials
    cursor.execute('DELETE FROM users')  # Clean slate
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('admin', 'admin123', 'admin@university.edu', 'admin'))
    
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('user', 'password', 'user@university.edu', 'user'))
    
    # NEW: Add student accounts for student login
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('john_student', 'student123', 'john.student@university.edu', 'student'))
    
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('sarah_student', 'student456', 'sarah.student@university.edu', 'student'))
    
    # Add student records that correspond to student logins
    cursor.execute('DELETE FROM students')  # Clean slate
    cursor.execute('''
        INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('10001', 'John Smith', 'john.student@university.edu', '9876543210', '123 Main St', '123-45-6789', 3.85, 'student123'))
    
    cursor.execute('''
        INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('10002', 'Sarah Johnson', 'sarah.student@university.edu', '9876543211', '456 Oak Ave', '987-65-4321', 3.92, 'student456'))
    
    cursor.execute('''
        INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', ('10003', 'Michael Brown', 'michael@university.edu', '9876543212', '789 Pine Rd', '456-78-9012', 3.45, 'pass123'))
    
    conn.commit()
    conn.close()
    print("[*] Database initialized successfully")

def authenticate_user(username, password):
    """
    FIXED: SQL Injection - Uses parameterized queries
    Description: Authenticates a user securely using prepared statements.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Using parameterized query to prevent SQL Injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    user = None
    try:
        cursor.execute(query, (username, password)) # Pass parameters as a tuple
        user = cursor.fetchone()
    except Exception as e:
        # Improved error handling, avoid revealing raw SQL errors to users/logs directly
        print(f"[ERROR] Database operation failed during authentication: {str(e)}")
    finally:
        conn.close()
    
    # Log AFTER closing connection to avoid database lock
    if user:
        log_action('AUTH_ATTEMPT', username, f"Result: Success") # Removed password from log for information disclosure
    else:
        log_action('AUTH_ATTEMPT', username, f"Result: Failed") # Removed password from log for information disclosure
    
    return user

def search_students(search_term):
    """
    FIXED: SQL Injection - Uses parameterized queries
    Description: Searches for students securely using parameterized queries.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Using parameterized query
    search_term_like = f"%{search_term}%" # Wildcards are part of the parameter value
    query = "SELECT id, name, email, phone, roll_no FROM students WHERE name LIKE ? OR roll_no LIKE ? OR email LIKE ?"
    
    try:
        cursor.execute(query, (search_term_like, search_term_like, search_term_like))
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        print(f"[ERROR] Secure search failed: {str(e)}")
        return []

def get_student_details(student_id):
    """
    FIXED: SQL Injection - Uses parameterized queries
    Description: Retrieves student details securely.
    VULNERABILITY: Still returns sensitive data (SSN, password) - Information Disclosure.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Using parameterized query
    query = "SELECT * FROM students WHERE id = ?"
    
    try:
        cursor.execute(query, (student_id,)) # Pass as a tuple
        student = cursor.fetchone()
        conn.close()
        # VULNERABLE: Returns sensitive data including SSN and password
        return student
    except Exception as e:
        print(f"[ERROR] Secure query for student details failed: {str(e)}")
        return None

def add_student(roll_no, name, email, phone, address, ssn, gpa):
    """
    FIXED: SQL Injection - Uses parameterized queries
    VULNERABILITY: Still lacks comprehensive input validation for data types/formats.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # SECURE: Using parameterized query
        query = '''
            INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        cursor.execute(query, (roll_no, name, email, phone, address, ssn, gpa, roll_no))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to securely add student: {str(e)}")
        return False

def log_action(action, username, details):
    """
    VULNERABILITY: Information Disclosure
    Logs sensitive details including passwords and personal info.
    This function itself already used parameterized queries, so no SQLi here.
    """
    try:
        conn = sqlite3.connect(DB_NAME, timeout=5.0)  # Wait up to 5 seconds for lock
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO logs (action, username, details) 
            VALUES (?, ?, ?)
        ''', (action, username, details))
        
        conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        # If database is locked, just print warning and continue
        print(f"[WARNING] Could not log action (database locked): {str(e)}")
        pass
