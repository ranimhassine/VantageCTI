from collectors.cisa_kev import get_cisa_kev
from database.connection import get_connection


def normalize_vulnerability(vulnerability):
    return {
        "cve_id": vulnerability["cveID"],
        "vendor": vulnerability["vendorProject"],
        "product": vulnerability["product"],
        "name": vulnerability["vulnerabilityName"],
        "description": vulnerability["shortDescription"],
        "date_added": vulnerability["dateAdded"],
        "source": "CISA KEV",
    }


def save_vulnerability(cursor, vulnerability):
    cursor.execute(
        """
        INSERT INTO vulnerabilities (
            cve_id,
            vendor,
            product,
            name,
            description,
            date_added,
            source
        )
        VALUES (
            %(cve_id)s,
            %(vendor)s,
            %(product)s,
            %(name)s,
            %(description)s,
            %(date_added)s,
            %(source)s
        )
        ON CONFLICT (cve_id)
        DO UPDATE SET
            vendor = EXCLUDED.vendor,
            product = EXCLUDED.product,
            name = EXCLUDED.name,
            description = EXCLUDED.description,
            date_added = EXCLUDED.date_added,
            source = EXCLUDED.source;
        """,
        vulnerability,
    )


def ingest_cisa_kev():
    print("Downloading CISA KEV catalog...")

    kev_data = get_cisa_kev()
    vulnerabilities = kev_data["vulnerabilities"]

    print(f"Received {len(vulnerabilities)} vulnerabilities.")
    print("Saving vulnerabilities to PostgreSQL...")

    connection = get_connection()
    cursor = connection.cursor()

    try:
        for vulnerability in vulnerabilities:
            normalized = normalize_vulnerability(vulnerability)
            save_vulnerability(cursor, normalized)

        connection.commit()

        print("CISA KEV ingestion completed successfully.")
        print(f"Processed: {len(vulnerabilities)} vulnerabilities.")

    except Exception:
        connection.rollback()
        print("Ingestion failed. Database changes were rolled back.")
        raise

    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    ingest_cisa_kev()