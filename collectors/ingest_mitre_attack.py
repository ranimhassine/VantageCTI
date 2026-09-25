from collectors.mitre_attack import (
    get_mitre_attack,
    normalize_attack_pattern,
)
from database.connection import get_connection


def save_attack_technique(cursor, technique):
    cursor.execute(
        """
        INSERT INTO attack_techniques (
            attack_id,
            stix_id,
            name,
            description,
            tactics,
            platforms,
            is_subtechnique,
            revoked,
            deprecated,
            created,
            modified,
            source,
            source_reference
        )
        VALUES (
            %(attack_id)s,
            %(stix_id)s,
            %(name)s,
            %(description)s,
            %(tactics)s,
            %(platforms)s,
            %(is_subtechnique)s,
            %(revoked)s,
            %(deprecated)s,
            %(created)s,
            %(modified)s,
            %(source)s,
            %(source_reference)s
        )
        ON CONFLICT (attack_id)
        DO UPDATE SET
            stix_id = EXCLUDED.stix_id,
            name = EXCLUDED.name,
            description = EXCLUDED.description,
            tactics = EXCLUDED.tactics,
            platforms = EXCLUDED.platforms,
            is_subtechnique = EXCLUDED.is_subtechnique,
            revoked = EXCLUDED.revoked,
            deprecated = EXCLUDED.deprecated,
            created = EXCLUDED.created,
            modified = EXCLUDED.modified,
            source = EXCLUDED.source,
            source_reference = EXCLUDED.source_reference;
        """,
        technique,
    )


def ingest_mitre_attack():
    print("Downloading MITRE ATT&CK dataset...")

    attack_data = get_mitre_attack()

    attack_patterns = [
        obj
        for obj in attack_data["objects"]
        if obj.get("type") == "attack-pattern"
    ]

    print(f"Received {len(attack_patterns)} attack-pattern objects.")
    print("Saving ATT&CK techniques to PostgreSQL...")

    connection = get_connection()
    cursor = connection.cursor()

    processed = 0
    skipped = 0

    try:
        for attack_pattern in attack_patterns:
            technique = normalize_attack_pattern(attack_pattern)

            if not technique["attack_id"]:
                skipped += 1
                continue

            save_attack_technique(cursor, technique)
            processed += 1

        connection.commit()

        print("MITRE ATT&CK ingestion completed successfully.")
        print(f"Processed: {processed}")
        print(f"Skipped: {skipped}")

    except Exception:
        connection.rollback()
        print("Ingestion failed. Database changes were rolled back.")
        raise

    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    ingest_mitre_attack()