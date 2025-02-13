from app import app, db, Admin
import os

def init_db():
    with app.app_context():
        # Create all tables
        db.drop_all()  # First drop all existing tables
        db.create_all()
        
        # Create admin user
        admin = Admin(username=os.getenv('ADMIN_USERNAME', 'admin'))
        admin.set_password(os.getenv('ADMIN_PASSWORD', 'doitinprod'))
        db.session.add(admin)
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db() 