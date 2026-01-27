def execute(strategies):
    results = {}
    for s in strategies:
        results[s["name"]] = "Detected" if s["risk"] > 5 else "Safe"
    return results

