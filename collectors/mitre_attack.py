import requests


MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)


def get_mitre_attack():
    response = requests.get(
        MITRE_ATTACK_URL,
        timeout=60,
    )

    response.raise_for_status()

    return response.json()


def get_mitre_external_reference(attack_pattern):
    for reference in attack_pattern.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference

    return {}


def normalize_attack_pattern(attack_pattern):
    mitre_reference = get_mitre_external_reference(attack_pattern)

    tactics = [
        phase.get("phase_name")
        for phase in attack_pattern.get("kill_chain_phases", [])
        if phase.get("phase_name")
    ]

    return {
        "attack_id": mitre_reference.get("external_id"),
        "stix_id": attack_pattern.get("id"),
        "name": attack_pattern.get("name"),
        "description": attack_pattern.get("description"),
        "tactics": tactics,
        "platforms": attack_pattern.get("x_mitre_platforms", []),
        "is_subtechnique": attack_pattern.get(
            "x_mitre_is_subtechnique",
            False,
        ),
        "revoked": attack_pattern.get("revoked", False),
        "deprecated": attack_pattern.get(
            "x_mitre_deprecated",
            False,
        ),
        "created": attack_pattern.get("created"),
        "modified": attack_pattern.get("modified"),
        "source": "MITRE ATT&CK",
        "source_reference": mitre_reference.get("url"),
    }


def summarize_attack_patterns(attack_patterns):
    total = len(attack_patterns)

    revoked = sum(
        1
        for obj in attack_patterns
        if obj.get("revoked", False)
    )

    deprecated = sum(
        1
        for obj in attack_patterns
        if obj.get("x_mitre_deprecated", False)
    )

    active = sum(
        1
        for obj in attack_patterns
        if not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    )

    subtechniques = sum(
        1
        for obj in attack_patterns
        if obj.get("x_mitre_is_subtechnique", False)
    )

    top_level = sum(
        1
        for obj in attack_patterns
        if not obj.get("x_mitre_is_subtechnique", False)
    )

    return {
        "total": total,
        "active": active,
        "revoked": revoked,
        "deprecated": deprecated,
        "subtechniques": subtechniques,
        "top_level": top_level,
    }


if __name__ == "__main__":
    attack_data = get_mitre_attack()

    attack_patterns = [
        obj
        for obj in attack_data["objects"]
        if obj.get("type") == "attack-pattern"
    ]

    summary = summarize_attack_patterns(attack_patterns)

    print("MITRE ATT&CK Enterprise dataset summary")
    print("---------------------------------------")
    print("Total attack-pattern objects:", summary["total"])
    print("Active:", summary["active"])
    print("Revoked:", summary["revoked"])
    print("Deprecated:", summary["deprecated"])
    print("Sub-techniques:", summary["subtechniques"])
    print("Top-level techniques:", summary["top_level"])