import os
import pytest
from app import app
from database import init_db, DB_NAME

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            # Ensure fresh schema by deleting old database file
            if os.path.exists(DB_NAME):
                try:
                    os.remove(DB_NAME)
                except Exception:
                    pass
            init_db()
        yield client

def test_homepage_loads(client):
    """Test that the homepage/login page loads correctly."""
    response = client.get('/')
    assert response.status_code == 200
    assert b"Login" in response.data

def test_dashboard_unauthenticated_redirect(client):
    """Test that unauthenticated users are redirected to login."""
    response = client.get('/dashboard')
    assert response.status_code == 302
    assert b"Redirecting" in response.data
    
def test_login_successful(client):
    """Test standard admin login functionality."""
    response = client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Dashboard" in response.data
    assert b"admin" in response.data
    
def test_search_feature(client):
    """Test standard search functionality after login."""
    client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    response = client.post('/search', data={'search': 'John'}, follow_redirects=True)
    assert response.status_code == 200
    assert b"John Smith" in response.data

def test_add_student(client):
    """Test adding a student as an admin."""
    # Login as admin
    client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    
    # Add a student
    student_data = {
        'roll_no': '12345',
        'name': 'Test Student',
        'email': 'test@student.com',
        'phone': '1234567890',
        'address': 'Test Address',
        'ssn': '000-00-0000',
        'gpa': '4.0'
    }
    response = client.post('/add_student', data=student_data, follow_redirects=True)
    
    # Verify success
    assert response.status_code == 200
    assert b"Student added successfully" in response.data or b"Dashboard" in response.data

def test_student_view_marks(client):
    """Test a student viewing their own marks."""
    # Login as a pre-populated student (john_student)
    client.post('/login', data={'username': 'john_student', 'password': 'student123'}, follow_redirects=True)
    
    # Access grades page
    response = client.get('/student/grades', follow_redirects=True)
    
    # Verify grades are visible
    assert response.status_code == 200
    assert b"John Smith" in response.data
    assert b"3.85" in response.data  # John's GPA

