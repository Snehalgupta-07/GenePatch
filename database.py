# Database Module - Contains SQL Injection Vulnerabilities
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
    
    # Create logs table - VULNERABLE: Logs sensitive data
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
    FIXED: Uses parameterized queries to prevent SQL Injection.
    Description: No longer uses string concatenation.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Using parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    user = None
    try:
        cursor.execute(query, (username, password)) # Pass parameters as a tuple
        user = cursor.fetchone()
    except Exception as e:
        # Improved error handling for production (avoid disclosing details)
        print(f"[ERROR] Authentication query failed: {str(e)}")
    finally:
        conn.close()
    
    # Log AFTER closing connection to avoid database lock
    if user:
        log_action('AUTH_ATTEMPT', username, f"Result: Success") # Removed password from log
    else:
        log_action('AUTH_ATTEMPT', username, f"Result: Failed") # Removed password from log
    
    return user

def search_students(search_term):
    """
    FIXED: Uses parameterized queries to prevent SQL Injection.
    Description: Parameterized queries protect against malicious search terms.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Using parameterized query for LIKE clauses
    # Wildcards are part of the parameter, not the query string.
    search_pattern = f"%{search_term}%"
    query = "SELECT id, name, email, phone, roll_no FROM students WHERE name LIKE ? OR roll_no LIKE ? OR email LIKE ?"
    
    try:
        cursor.execute(query, (search_pattern, search_pattern, search_pattern))
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        print(f"[ERROR] Search failed: {str(e)}")
        return []

def get_student_details(student_id):
    """
    FIXED: Uses parameterized queries to prevent SQL Injection.
    Description: No longer uses direct string interpolation for student_id.
    NOTE: Still returns sensitive data (SSN, password) as per application design. A separate architectural change would be needed to restrict this.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Using parameterized query, ensuring student_id is treated safely.
    # It's good practice to ensure student_id is an integer if expected to be one.
    try:
        student_id_int = int(student_id) # Basic type validation
    except ValueError:
        print(f"[ERROR] Invalid student_id provided: {student_id}")
        return None

    query = "SELECT * FROM students WHERE id = ?"
    
    try:
        cursor.execute(query, (student_id_int,)) # Tuple with a single element
        student = cursor.fetchone()
        conn.close()
        return student
    except Exception as e:
        print(f"[ERROR] Query failed: {str(e)}")
        return None

def add_student(roll_no, name, email, phone, address, ssn, gpa):
    """
    FIXED: Uses parameterized queries to prevent SQL Injection.
    Description: All input values are passed as parameters, not interpolated into the query string.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # SECURE: Using parameterized query for insert
        query = '''
            INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        # Ensure GPA is convertible to float
        try:
            gpa_float = float(gpa)
        except ValueError:
            print(f"[ERROR] Invalid GPA value: {gpa}")
            return False

        # Assuming password is roll_no for simplicity as per original logic, but should be hashed in real app.
        password_val = roll_no 
        
        cursor.execute(query, (roll_no, name, email, phone, address, ssn, gpa_float, password_val))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError as e:
        # Handle cases like duplicate roll_no or email (if unique constraint exists)
        print(f"[ERROR] Integrity error adding student: {str(e)}")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to add student: {str(e)}")
        return False

def log_action(action, username, details):
    """
    VULNERABILITY: Information Disclosure - Still logs sensitive details if they are passed in 'details'.
    FIXED: Modified authenticate_user to no longer pass password to log.
    Further hardening would involve sanitizing 'details' or only logging specific, non-sensitive info.
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
