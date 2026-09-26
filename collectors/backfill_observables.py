from collectors.observable_correlation import correlate_url_indicator
from database.connection import get_connection


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

        print(f"Found {len(indicators)} URL indicators.")
        print("Extracting and correlating host observables...")

        for indicator in indicators:
            indicator_id = indicator[0]
            value = indicator[1]
            first_seen = indicator[2]
            last_seen = indicator[3]

            correlated = correlate_url_indicator(
                write_cursor,
                indicator_id,
                value,
                first_seen,
                last_seen,
            )

            if correlated:
                processed += 1
            else:
                skipped += 1

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