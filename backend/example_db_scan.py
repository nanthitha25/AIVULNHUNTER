"""
Example script showing how to use the database-backed scan pipeline
"""

import sys
from pathlib import Path

# Add backend to path
sys.path.append(str(Path(__file__).resolve().parent))

from backend.services.scan_pipeline_db import run_scan_pipeline, get_scan_result
from backend.database.connection import check_connection
import time

def main():
    print("🔍 AivulnHunter - Database-Backed Scan Example")
    print("=" * 60)
    
    # Check database connection
    print("\n1️⃣ Checking database connection...")
    if not check_connection():
        print("❌ Cannot connect to database!")
        print("   Please run: python3 backend/database/migrate.py")
        return
    print("✅ Database connected")
    
    # Start scan
    target = "http://localhost:9000/chat"
    print(f"\n2️⃣ Starting scan against {target}...")
    
    result = run_scan_pipeline(target=target)
    scan_id = result["scan_id"]
    
    print(f"✅ Scan started with ID: {scan_id}")
    print(f"   Status: {result['status']}")
    
    # Poll for results
    print("\n3️⃣ Waiting for scan to complete...")
    max_wait = 60  # seconds
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        scan_data = get_scan_result(scan_id)
        
        if not scan_data:
            print("❌ Scan not found!")
            return
        
        status = scan_data["status"]
        print(f"   Status: {status}", end="\r")
        
        if status in ["completed", "failed"]:
            break
        
        time.sleep(2)
    
    # Display results
    print(f"\n\n4️⃣ Scan Results")
    print("=" * 60)
    
    scan_data = get_scan_result(scan_id)
    
    print(f"Target: {scan_data['target']}")
    print(f"Status: {scan_data['status']}")
    print(f"Duration: {scan_data.get('duration_seconds', 0)} seconds")
    print(f"Rules Tested: {scan_data.get('total_rules_tested', 0)}")
    print(f"Vulnerabilities Found: {scan_data.get('vulnerabilities_found', 0)}")
    
    print(f"\n📋 Detailed Findings:")
    print("-" * 60)
    
    for vuln in scan_data["results"]:
        severity = vuln.get('severity', 'UNKNOWN')
        name = vuln.get('name', 'Unknown')
        status = vuln.get('status', 'UNKNOWN')
        
        if status == "VULNERABLE":
            print(f"\n🔴 [{severity}] {name} ({vuln.get('owasp', 'N/A')})")
            print(f"   Confidence: {vuln.get('confidence', 0):.2f}")
            print(f"   Explanation: {vuln.get('explanation', 'N/A')}")
            print(f"   Mitigation: {vuln.get('mitigation', 'N/A')}")
        elif status == "SECURE":
            print(f"🟢 [SECURE] {name}")
        else:
            print(f"⚪ [{status}] {name}")
    
    print("\n" + "=" * 60)
    print("✅ Scan complete! Results stored in database.")
    print(f"   Scan ID: {scan_id}")

if __name__ == "__main__":
    main()
