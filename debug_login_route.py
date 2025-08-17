from app import app
from models import User, db
from flask import request, flash
from datetime import datetime
from flask_login import login_user

# Add this debug function to routes.py temporarily
def debug_login_process():
    """Debug version of login process"""
    print("\n=== DEBUG LOGIN PROCESS ===")
    
    # Get form data
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    csrf_token = request.form.get('csrf_token', '')
    
    print(f"Form data received:")
    print(f"  Username: '{username}' (length: {len(username)})")
    print(f"  Password: '{password}' (length: {len(password)})")
    print(f"  CSRF Token: '{csrf_token[:20]}...' (length: {len(csrf_token)})")
    
    # Check if fields are empty
    if not username:
        print("ERROR: Username is empty!")
        return False
    if not password:
        print("ERROR: Password is empty!")
        return False
        
    # Query user
    print(f"\nQuerying user with username: '{username}'")
    user = User.query.filter_by(username=username).first()
    print(f"User found: {user is not None}")
    
    if user:
        print(f"User details:")
        print(f"  ID: {user.id}")
        print(f"  Username: '{user.username}'")
        print(f"  Email: '{user.email}'")
        print(f"  Is Admin: {user.is_admin}")
        print(f"  Is Active: {user.is_active}")
        
        # Test password
        password_valid = user.check_password(password)
        print(f"  Password check result: {password_valid}")
        
        if password_valid:
            print("LOGIN SUCCESS: User and password are valid")
            try:
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user)
                print("User logged in successfully")
                return True
            except Exception as e:
                print(f"ERROR during login_user: {e}")
                return False
        else:
            print("LOGIN FAILED: Invalid password")
            return False
    else:
        print("LOGIN FAILED: User not found")
        return False

if __name__ == "__main__":
    print("This is a debug helper script. Add the debug_login_process() function to your routes.py")