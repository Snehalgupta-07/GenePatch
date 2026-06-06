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
    SECURE: Uses parameterized queries to prevent SQL Injection.
    Does not log sensitive details like passwords.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: SQL Injection fixed - Use parameterized queries
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    user = None
    try:
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
    except Exception as e:
        # Avoid detailed error messages. Log internally, but do not expose to user.
        print(f"[ERROR] Authentication failed: {str(e)}")
    finally:
        conn.close()  # Ensure connection is always closed
    
    # Log action outside try-finally to ensure connection is closed before logging
    # SECURE: Do not log sensitive data like passwords in details
    log_action('AUTH_ATTEMPT', username, f"Result: {'Success' if user else 'Failed'}")
    
    return user

def search_students(search_term):
    """
    SECURE: Uses parameterized queries to prevent SQL Injection.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: SQL Injection fixed - Use parameterized queries for LIKE clauses
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
    SECURE: Uses parameterized queries to prevent SQL Injection.
    Avoids sensitive data exposure by explicitly selecting columns.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SECURE: SQL Injection fixed - Use parameterized query
    # SECURE: Avoid Sensitive Data Exposure - Only select necessary, non-sensitive columns
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
    SECURE: Uses parameterized queries to prevent SQL Injection.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # SECURE: SQL Injection fixed - Use parameterized query
        # Note: Password handling here is still weak (using roll_no as password).
        # For a full secure solution, passwords should be hashed and salted.
        query = '''
            INSERT INTO students (roll_no, name, email, phone, address, ssn, gpa, password) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        cursor.execute(query, (roll_no, name, email, phone, address, ssn, gpa, roll_no))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to add student: {str(e)}")
        return False

def log_action(action, username, details):
    """
    SECURE: This function logs provided details. It is the responsibility
    of the calling function to ensure 'details' do not contain sensitive information.
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
        # If database is locked, just print warning and continue. 
        # In a production environment, consider a more robust logging strategy.
        print(f"[WARNING] Could not log action (database locked): {str(e)}")
        pass
