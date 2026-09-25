from collectors.urlhaus import (
    get_urlhaus_recent,
    parse_urlhaus_csv,
    normalize_urlhaus_record,
)
from database.connection import get_connection


def save_indicator(cursor, indicator):
    cursor.execute(
        """
        INSERT INTO indicators (
            type,
            value,
            status,
            threat_type,
            malware_family,
            first_seen,
            last_seen,
            source,
            source_id,
            source_reference
        )
        VALUES (
            %(type)s,
            %(value)s,
            %(status)s,
            %(threat_type)s,
            %(malware_family)s,
            %(first_seen)s,
            %(last_seen)s,
            %(source)s,
            %(source_id)s,
            %(source_reference)s
        )
        ON CONFLICT (source, source_id)
        DO UPDATE SET
            type = EXCLUDED.type,
            value = EXCLUDED.value,
            status = EXCLUDED.status,
            threat_type = EXCLUDED.threat_type,
            malware_family = EXCLUDED.malware_family,
            first_seen = EXCLUDED.first_seen,
            last_seen = EXCLUDED.last_seen,
            source_reference = EXCLUDED.source_reference;
        """,
        indicator,
    )


def ingest_urlhaus():
    print("Downloading URLhaus recent feed...")

    csv_data = get_urlhaus_recent()
    records = parse_urlhaus_csv(csv_data)

    print(f"Received {len(records)} URLhaus records.")
    print("Saving indicators to PostgreSQL...")

    connection = get_connection()
    cursor = connection.cursor()

    try:
        for record in records:
            indicator = normalize_urlhaus_record(record)
            save_indicator(cursor, indicator)

        connection.commit()

        print("URLhaus ingestion completed successfully.")
        print(f"Processed: {len(records)} indicators.")

    except Exception:
        connection.rollback()
        print("Ingestion failed. Database changes were rolled back.")
        raise

    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    ingest_urlhaus()