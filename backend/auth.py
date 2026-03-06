import bcrypt

# Hardcoded bcrypt hashes for credentials (generated with bcrypt.hashpw)
ADMIN_HASH = '$2b$12$E5O22h.k.goKEXqjn8k0heyjVvHVUtxYeTf4qdCsWs1SCbjnsiWtW'
USER_HASH = '$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'

print(f"=== FRESH HASHES ===")
print(f"admin123 hash: {ADMIN_HASH}")
print(f"user123 hash: {USER_HASH}")

def get_password_hash(password: str):
    """Hash a password using bcrypt."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
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
        "hashed_password": ADMIN_HASH,
        "role": "admin"
    },
    "user": {
        "username": "user",
        "hashed_password": USER_HASH,
        "role": "user"
    }
}

