"""
Authentication Module

Handles admin authentication using credentials from admin_config.
"""

from admin_config import ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_TOKEN


def authenticate(username: str, password: str):
    """Authenticate admin credentials.
    
    Args:
        username: Admin username
        password: Admin password
        
    Returns:
        Admin token if credentials are valid, None otherwise
    """
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return ADMIN_TOKEN
    return None


def verify_token(token: str):
    """Verify if the provided token is valid.
    
    Args:
        token: Token to verify
        
    Returns:
        True if token is valid, False otherwise
    """
    return token == ADMIN_TOKEN

