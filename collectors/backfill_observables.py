from collectors.observable_utils import extract_url_host
from database.connection import get_connection


RELATIONSHIP_TYPE = "extracted_host"


def save_observable(cursor, observable_type, value, first_seen, last_seen):
    cursor.execute(
        """
        INSERT INTO observables (
            type,
            value,
            first_seen,
            last_seen
        )
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (type, value)
        DO UPDATE SET
            first_seen = CASE
                WHEN observables.first_seen IS NULL
                    THEN EXCLUDED.first_seen
                WHEN EXCLUDED.first_seen IS NULL
                    THEN observables.first_seen
                ELSE LEAST(
                    observables.first_seen,
                    EXCLUDED.first_seen
                )
            END,
            last_seen = CASE
                WHEN observables.last_seen IS NULL
                    THEN EXCLUDED.last_seen
                WHEN EXCLUDED.last_seen IS NULL
                    THEN observables.last_seen
                ELSE GREATEST(
                    observables.last_seen,
                    EXCLUDED.last_seen
                )
            END
        RETURNING id;
        """,
        (
            observable_type,
            value,
            first_seen,
            last_seen,
        ),
    )

    return cursor.fetchone()[0]


def save_relationship(cursor, indicator_id, observable_id):
    cursor.execute(
        """
        INSERT INTO indicator_observables (
            indicator_id,
            observable_id,
            relationship_type
        )
        VALUES (%s, %s, %s)
        ON CONFLICT (
            indicator_id,
            observable_id,
            relationship_type
        )
        DO NOTHING;
        """,
        (
            indicator_id,
            observable_id,
            RELATIONSHIP_TYPE,
        ),
    )


def backfill_observables():
    connection = get_connection()
    read_cursor = connection.cursor()
    write_cursor = connection.cursor()

    try:
        read_cursor.execute(
            """
            SELECT
                id,
                value,
                first_seen,
                last_seen
            FROM indicators
            WHERE type = 'url'
            ORDER BY id;
            """
        )

        indicators = read_cursor.fetchall()

        processed = 0
        skipped = 0

        print(
            f"Found {len(indicators)} URL indicators."
        )
        print("Extracting and correlating host observables...")

        for indicator in indicators:
            indicator_id = indicator[0]
            value = indicator[1]
            first_seen = indicator[2]
            last_seen = indicator[3]

            extracted = extract_url_host(value)

            host = extracted["host"]
            host_type = extracted["host_type"]

            if not host or not host_type:
                skipped += 1
                continue

            observable_id = save_observable(
                write_cursor,
                host_type,
                host,
                first_seen,
                last_seen,
            )

            save_relationship(
                write_cursor,
                indicator_id,
                observable_id,
            )

            processed += 1

        connection.commit()

        print("Observable backfill completed successfully.")
        print(f"Processed: {processed}")
        print(f"Skipped: {skipped}")

    except Exception:
        connection.rollback()

        print(
            "Observable backfill failed. "
            "Database changes were rolled back."
        )

        raise

    finally:
        read_cursor.close()
        write_cursor.close()
        connection.close()


if __name__ == "__main__":
    backfill_observables()