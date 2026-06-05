# Configuration File - Intentionally Vulnerable
import os

class Config:
    # SQL INJECTION VULNERABILITY: Using raw SQL queries
    # Path Traversal & Insecure Upload: No restrictions on upload paths
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx', 'exe', 'sh', 'bat'}  # VULNERABLE: Allows executable files
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB - No proper file size validation
    
    
    # Sensitive Data Exposure: Weak secret key
    SECRET_KEY = 'super_secret_key_12345'  # VULNERABLE: Hardcoded weak secret
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///vulnerable_app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    
    # Session Configuration - VULNERABLE
    # Using Flask built-in sessions instead of Flask-Session
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours in seconds
    SESSION_COOKIE_HTTPONLY = False  # VULNERABLE: Disabling HttpOnly allows JavaScript to read the session cookie
