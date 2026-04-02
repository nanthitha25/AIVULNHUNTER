import bcrypt
from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal
from backend.database.models import User

def check_users():
    db = SessionLocal()
    users = db.query(User).all()
    for u in users:
        print(f"User: {u.username}")
        # check if it matches demo123 or user123
        try:
            if bcrypt.checkpw(b"demo123", u.hashed_password.encode('utf-8')):
                print("  Password: demo123")
            elif bcrypt.checkpw(b"user123", u.hashed_password.encode('utf-8')):
                print("  Password: user123")
            else:
                print("  Password: unknown")
        except:
            print("  Could not check password against known values")
    db.close()

if __name__ == "__main__":
    check_users()
