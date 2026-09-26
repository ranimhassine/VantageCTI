from collectors.observable_correlation import correlate_url_indicator
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
            tags,
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
            %(tags)s,
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
            tags = EXCLUDED.tags,
            first_seen = EXCLUDED.first_seen,
            last_seen = EXCLUDED.last_seen,
            source_reference = EXCLUDED.source_reference
        RETURNING id;
        """,
        indicator,
    )

    return cursor.fetchone()[0]


def ingest_urlhaus():
    print("Downloading URLhaus recent feed...")

    csv_data = get_urlhaus_recent()
    records = parse_urlhaus_csv(csv_data)

    print(f"Received {len(records)} URLhaus records.")
    print("Saving indicators and correlating observables...")

    connection = get_connection()
    cursor = connection.cursor()

    try:
        processed = 0
        correlated = 0
        skipped_correlation = 0

        for record in records:
            indicator = normalize_urlhaus_record(record)

            indicator_id = save_indicator(
                cursor,
                indicator,
            )

            correlation_created = correlate_url_indicator(
                cursor,
                indicator_id,
                indicator["value"],
                indicator["first_seen"],
                indicator["last_seen"],
            )

            processed += 1

            if correlation_created:
                correlated += 1
            else:
                skipped_correlation += 1

        connection.commit()

        print("URLhaus ingestion completed successfully.")
        print(f"Processed: {processed} indicators.")
        print(f"Correlated: {correlated}")
        print(
            "Skipped correlation: "
            f"{skipped_correlation}"
        )

    except Exception:
        connection.rollback()

        print(
            "Ingestion failed. "
            "Database changes were rolled back."
        )

        raise

    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    ingest_urlhaus()