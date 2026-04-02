import sqlite3
import os

def get_connection():
    # Correct path to aivuln.db in the root
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "aivuln.db")
    return sqlite3.connect(db_path)
