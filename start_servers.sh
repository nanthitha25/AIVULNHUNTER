#!/bin/bash
export PYTHONPATH=/Users/nanthithavenkatachapathy/Desktop/AivulnHunter:/Users/nanthithavenkatachapathy/Desktop/AivulnHunter/backend
nohup ./venv/bin/python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 > backend.log 2>&1 &
echo $! > backend.pid

nohup ./venv/bin/python3 -m uvicorn mock_targets:app --host 0.0.0.0 --port 8080 > mock8080.log 2>&1 &
echo $! > mock8080.pid

nohup ./venv/bin/python3 -m uvicorn mock_targets:app --host 0.0.0.0 --port 9001 > mock9001.log 2>&1 &
echo $! > mock9001.pid

echo "Servers started."
