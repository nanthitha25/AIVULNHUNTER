#!/bin/bash
echo "=== Test 1: URL Input ==="
curl -s -X POST http://localhost:8000/assistant/chat \
-H "Content-Type: application/json" \
-d '{
"message": "Analyze this target for vulnerabilities",
"scan_context": "https://example.com/login",
"file_type": "url"
}' | jq .

echo -e "\n=== Test 2: JSON Input ==="
curl -s -X POST http://localhost:8000/assistant/chat \
-H "Content-Type: application/json" \
-d '{
"message": "Analyze this scan result",
"scan_context": "{\"endpoint\":\"/login\", \"payload\":\" OR 1=1--\"}",
"file_type": "json"
}' | jq .

echo -e "\n=== Test 3: CSV Input ==="
curl -s -X POST http://localhost:8000/assistant/chat \
-H "Content-Type: application/json" \
-d '{
"message": "Identify vulnerabilities",
"scan_context": "endpoint,parameter,payload,response_code\n/login,username,OR 1=1--,200\n/search,q,<script>alert(1)</script>,200",
"file_type": "csv"
}' | jq .
