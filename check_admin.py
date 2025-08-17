from app import app
from models import User, db

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    print(f'Admin user exists: {admin is not None}')
    
    if admin:
        print(f'Username: {admin.username}')
        print(f'Email: {admin.email}')
        print(f'Is admin: {admin.is_admin}')
        print(f'Password check with "AdminPass123!": {admin.check_password("AdminPass123!")}')
        print(f'Password hash: {admin.password_hash[:50]}...')
    else:
        print('Admin user not found in database')
        print('Creating admin user...')
        admin = User(
            username='admin',
            email='admin@phishguard.com',
            is_admin=True
        )
        admin.set_password('AdminPass123!')
        db.session.add(admin)
        db.session.commit()
        print('Admin user created successfully!')