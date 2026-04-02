import sys
import os
sys.path.append(os.getcwd())
from backend.main import app

for route in app.routes:
    print(route.path, route.name)
