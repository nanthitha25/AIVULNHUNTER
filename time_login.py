import time
import requests

start = time.time()
try:
    res = requests.post("http://localhost:8000/api/v1/auth/login", json={"username": "user", "password": "user123"})
    print("Status:", res.status_code)
    print("Time taken:", time.time() - start)
except Exception as e:
    print("Error:", e)
