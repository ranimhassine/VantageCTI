import argparse
import time

from collectors.ipinfo import get_ip_enrichment
from database.connection import get_connection


def save_enrichment(
    cursor,
    observable_id,
    enrichment,
):
    cursor.execute(
        """
        INSERT INTO observable_enrichments (
            observable_id,
            provider,
            asn,
            as_name,
            as_domain,
            country_code,
            country,
            continent_code,
            continent,
            retrieved_at
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            NOW()
        )
        ON CONFLICT (
            observable_id,
            provider
        )
        DO UPDATE SET
            asn = EXCLUDED.asn,
            as_name = EXCLUDED.as_name,
            as_domain = EXCLUDED.as_domain,
            country_code = EXCLUDED.country_code,
            country = EXCLUDED.country,
            continent_code = EXCLUDED.continent_code,
            continent = EXCLUDED.continent,
            retrieved_at = NOW();
        """,
        (
            observable_id,
            enrichment["provider"],
            enrichment["asn"],
            enrichment["as_name"],
            enrichment["as_domain"],
            enrichment["country_code"],
            enrichment["country"],
            enrichment["continent_code"],
            enrichment["continent"],
        ),
    )


def enrich_ip_observables(
    limit=None,
    refresh=False,
):
    connection = get_connection()
    read_cursor = connection.cursor()
    write_cursor = connection.cursor()

    try:
        query = """
            SELECT
                o.id,
                o.value
            FROM observables o
            WHERE o.type = 'ip'
        """

        parameters = []

        if not refresh:
            query += """
                AND NOT EXISTS (
                    SELECT 1
                    FROM observable_enrichments oe
                    WHERE
                        oe.observable_id = o.id
                        AND oe.provider = 'IPinfo'
                )
            """

        query += """
            ORDER BY o.id
        """

        if limit is not None:
            query += " LIMIT %s"
            parameters.append(limit)

        query += ";"

        read_cursor.execute(
            query,
            parameters,
        )

        observables = read_cursor.fetchall()

        print(
            f"Found {len(observables)} IP observables "
            "to enrich."
        )

        enriched = 0
        failed = 0

        for observable_id, ip_address in observables:
            try:
                enrichment = get_ip_enrichment(
                    ip_address
                )

                save_enrichment(
                    write_cursor,
                    observable_id,
                    enrichment,
                )

                connection.commit()

                enriched += 1

                print(
                    f"[{enriched + failed}/"
                    f"{len(observables)}] "
                    f"Enriched {ip_address}"
                )

            except Exception as exc:
                connection.rollback()

                failed += 1

                print(
                    f"[{enriched + failed}/"
                    f"{len(observables)}] "
                    f"Failed {ip_address}: {exc}"
                )

            time.sleep(0.05)

        print()
        print("IP enrichment completed.")
        print(f"Enriched: {enriched}")
        print(f"Failed: {failed}")

    finally:
        read_cursor.close()
        write_cursor.close()
        connection.close()


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Enrich normalized IP observables "
            "using IPinfo."
        )
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Maximum number of IP observables "
            "to process."
        ),
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "Refresh IPinfo enrichment even when "
            "a record already exists."
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    enrich_ip_observables(
        limit=args.limit,
        refresh=args.refresh,
    )