from app import app
from models import User, db

with app.app_context():
    # Test the exact login process
    username = 'admin'
    password = 'AdminPass123!'
    
    print(f"Testing login with username: '{username}' and password: '{password}'")
    
    # Query the user
    user = User.query.filter_by(username=username).first()
    print(f"User found: {user is not None}")
    
    if user:
        print(f"User details:")
        print(f"  - ID: {user.id}")
        print(f"  - Username: '{user.username}'")
        print(f"  - Email: '{user.email}'")
        print(f"  - Is Admin: {user.is_admin}")
        print(f"  - Is Active: {user.is_active}")
        print(f"  - Password Hash: {user.password_hash[:50]}...")
        
        # Test password check
        password_check = user.check_password(password)
        print(f"Password check result: {password_check}")
        
        # Test with different variations
        print("\nTesting password variations:")
        variations = [
            'AdminPass123!',
            'adminpass123!',
            'ADMINPASS123!',
            'AdminPass123',
            'admin',
            'Admin123!'
        ]
        
        for pwd in variations:
            result = user.check_password(pwd)
            print(f"  '{pwd}': {result}")
    else:
        print("No user found with that username")
        
    # Also test case sensitivity for username
    print("\nTesting username variations:")
    username_variations = ['admin', 'Admin', 'ADMIN', 'administrator']
    
    for uname in username_variations:
        user_test = User.query.filter_by(username=uname).first()
        print(f"  Username '{uname}': {'Found' if user_test else 'Not found'}")