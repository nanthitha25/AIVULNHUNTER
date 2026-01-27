def decide_strategy(profile, rules):
    return [r for r in rules if r["target_type"] == profile["type"]]

