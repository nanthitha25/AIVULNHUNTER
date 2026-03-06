import bcrypt

# Pre-computed bcrypt hash for admin/admin123
# This hash is consistent across server restarts
ADMIN_HASH = b'$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.dW8KIuJ3eHFfTi'
USER_HASH = b'$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'

def get_password_hash(password: str):
    """Hash a password using bcrypt."""
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, ADMIN_HASH)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    """Verify a password against a hash."""
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

# In-memory user database with FIXED hashed passwords
# Admin credentials: admin / admin123
# User credentials: user / user123
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": ADMIN_HASH.decode('utf-8'),
        "role": "admin"
    },
    "user": {
        "username": "user",
        "hashed_password": USER_HASH.decode('utf-8'),
        "role": "user"
    }
}

