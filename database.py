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
    
    # Create logs table - VULNERABLE: Logs sensitive data (Content of log fixed by modifying calls)
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
    FIXED: SQL Injection - Uses parameterized queries.
    FIXED: Information Disclosure - Removed password from internal error messages and logs.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Use parameterized query to prevent SQL Injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    user = None
    try:
        cursor.execute(query, (username, password)) # Pass parameters as a tuple
        user = cursor.fetchone()
    except Exception as e:
        # Avoid exposing internal error messages to stdout in production, but keep for internal debugging.
        print(f"[ERROR] Authentication failed: {str(e)}")
    finally:
        conn.close()
    
    # Log action without sensitive password details. 
    # (Note: The log_action calls in app.py's `login` route would also need to be updated in a full fix.)
    if user:
        log_action('AUTH_ATTEMPT', username, "Result: Success")
    else:
        log_action('AUTH_ATTEMPT', username, "Result: Failed")
    
    return user

def search_students(search_term):
    """
    FIXED: SQL Injection - Uses parameterized queries.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Use parameterized query
    # Add '%' wildcard characters to the parameter itself, not the query string.
    param = f'%{search_term}%'
    query = "SELECT id, name, email, phone, roll_no FROM students WHERE name LIKE ? OR roll_no LIKE ? OR email LIKE ?"
    
    try:
        cursor.execute(query, (param, param, param))
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        print(f"[ERROR] Search failed: {str(e)}")
        return []

def get_student_details(student_id):
    """
    FIXED: SQL Injection - Uses parameterized queries.
    FIXED: Sensitive Data Exposure - Selects only non-sensitive columns (no SSN, no password).
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: Use parameterized query and explicitly select non-sensitive columns
    query = "SELECT id, roll_no, name, email, phone, address, gpa FROM students WHERE id = ?"
    
    try:
        cursor.execute(query, (student_id,))
        student = cursor.fetchone()
        conn.close()
        return student
    except Exception as e:
        print(f"[ERROR] Query failed: {str(e)}")
        return None

def add_student(roll_no, name, email, phone, address, ssn, gpa):
    """
    FIXED: SQL Injection - Uses parameterized queries.
    NOTE: Input validation (e.g., email format, SSN format, GPA range) is still recommended
          in the application layer (app.py) for a complete solution.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # SECURE: Use parameterized query
        query = '''
            INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        # Ensure GPA is stored as a float. A ValueError might occur if gpa isn't convertible.
        cursor.execute(query, (roll_no, name, email, phone, address, ssn, float(gpa), roll_no))
        
        conn.commit()
        conn.close()
        return True
    except ValueError:
        print(f"[ERROR] Failed to add student: Invalid GPA value '{gpa}'.")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to add student: {str(e)}")
        return False

def log_action(action, username, details):
    """
    FIXED: Information Disclosure (partially, by modifying calls to this function in authenticate_user).
    This function itself uses parameterized queries, which is secure. The vulnerability was in
    *what* data was passed to `details`.
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
        print(f"[WARNING] Could not log action (database locked): {str(e)}")
        pass
    except Exception as e:
        print(f"[ERROR] Failed to log action: {str(e)}")
