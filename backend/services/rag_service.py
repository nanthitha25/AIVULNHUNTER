"""
Retrieval-Augmented Generation (RAG) Service

Provides the knowledge retrieval layer for the AI Security Assistant.
Responsible for querying the local SQLite databases (`rules` and `scan_results`) 
and formatting them as context for the LLM.
"""

from typing import List, Dict, Optional
from backend.database.sqlite_db import get_connection

def get_rule_knowledge(keyword: str) -> str:
    """
    Search the rules database for specific vulnerability keywords.
    Returns a formatted string of matched rules to be used as context.
    """
    if not keyword or len(keyword) < 3:
        return ""
        
    conn = get_connection()
    # Simple keyword search across name and description
    query = """
    SELECT name, owasp_category, severity, description, mitigation 
    FROM rules 
    WHERE name LIKE ? OR description LIKE ?
    LIMIT 3
    """
    search_term = f"%{keyword}%"
    rows = conn.execute(query, (search_term, search_term)).fetchall()
    conn.close()
    
    if not rows:
        return ""
        
    context_chunks = []
    for row in rows:
        chunk = (
            f"Rule Name: {row['name']}\n"
            f"OWASP Category: {row['owasp_category']}\n"
            f"Severity: {row['severity']}\n"
            f"Description: {row['description']}\n"
            f"Mitigation: {row['mitigation']}\n"
        )
        context_chunks.append(chunk)
        
    return "Relevant Vulnerability Knowledge:\n" + "\n---\n".join(context_chunks)


def get_scan_context(scan_id: str) -> str:
    """
    Retrieve all vulnerability results for a specific scan to analyze.
    Returns a formatted string to be injected into the LLM context.
    """
    conn = get_connection()
    # Fetch the target metadata
    scan = conn.execute("SELECT target, target_type FROM scans WHERE id = ?", (scan_id,)).fetchone()
    
    if not scan:
        conn.close()
        return "Scan ID not found."
    
    # Fetch the vulnerable results 
    results = conn.execute(
        """SELECT rule_name, severity, explanation, evidence, mitigation, risk_score 
           FROM scan_results 
           WHERE scan_id = ? AND status = 'VULNERABLE'
           ORDER BY risk_score DESC""", 
        (scan_id,)
    ).fetchall()
    conn.close()

    context = f"Target Scanned: {scan['target']} (Type: {scan['target_type']})\n\n"
    
    if not results:
        context += "No vulnerabilities were detected in this scan."
        return context
        
    context += f"Detected {len(results)} Vulnerabilities:\n\n"
    
    for idx, r in enumerate(results, 1):
        context += (
            f"{idx}. {r['rule_name']} (Severity: {r['severity']}, Risk Score: {r['risk_score']})\n"
            f"   Explanation: {r['explanation']}\n"
            f"   Evidence Log: {r['evidence']}\n"
            f"   Recommended Mitigation: {r['mitigation']}\n\n"
        )
        
    return context
