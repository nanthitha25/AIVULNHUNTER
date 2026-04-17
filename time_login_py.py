import urllib.request
import json
import time

url = 'http://127.0.0.1:8000/api/v1/auth/login'
data = json.dumps({'username': 'admin', 'password': 'admin123'}).encode('utf-8')
headers = {'Content-Type': 'application/json'}
req = urllib.request.Request(url, data=data, headers=headers, method='POST')

start = time.time()
try:
    with urllib.request.urlopen(req) as f:
        print("Status", f.status)
        print("Time", time.time() - start)
except Exception as e:
    print(e)
    print("Time", time.time() - start)
