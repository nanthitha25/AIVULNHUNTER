from database.sqlite_db import get_connection

def search_rules(keyword: str):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
    SELECT name, description, mitigation, severity
    FROM rules
    WHERE name LIKE ? OR description LIKE ?
    """

    cursor.execute(query, (f"%{keyword}%", f"%{keyword}%"))
    results = cursor.fetchall()

    conn.close()

    return results


def get_scan_results(scan_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
    SELECT r.name, r.severity, sr.details
    FROM scan_results sr
    JOIN rules r ON sr.rule_id = r.id
    WHERE sr.scan_id = ?
    """

    cursor.execute(query, (scan_id,))
    results = cursor.fetchall()

    conn.close()

    return results
