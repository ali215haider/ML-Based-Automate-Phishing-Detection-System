from app import app, db
from models import User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Check if test user exists
    user = User.query.filter_by(email='test@example.com').first()
    print(f'User exists: {user is not None}')
    
    if not user:
        # Create test user
        user = User(
            username='testuser',
            email='test@example.com'
        )
        user.set_password('Password123!')
        db.session.add(user)
        db.session.commit()
        print('Test user created successfully')
    else:
        print(f'Test user already exists with ID: {user.id}')