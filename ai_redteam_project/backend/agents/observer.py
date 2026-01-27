def explain(results):
    report = {}
    for k, v in results.items():
        report[k] = {
            "status": v,
            "mitigation": "Apply OWASP recommended security control"
        }
    return report

