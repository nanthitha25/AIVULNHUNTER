from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal
from backend.database.models import User
import bcrypt

def ensure_admin():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode('utf-8')
        
        if not user:
            print("Admin user not found. Creating a new one...")
            user = User(
                username="admin",
                email="admin@aivulnhunter.remote",
                hashed_password=hashed,
                role="admin",
                is_active=True
            )
            db.add(user)
            db.commit()
            print("✅ Admin user 'admin' created with password 'admin123'.")
        else:
            print("Admin user found. Resetting password to 'admin123'...")
            user.hashed_password = hashed
            db.commit()
            print("✅ Admin user 'admin' password has been reset to 'admin123'.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    ensure_admin()
