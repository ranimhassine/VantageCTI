from collectors.observable_utils import extract_url_host


EXTRACTED_HOST_RELATIONSHIP = "extracted_host"


def save_observable(
    cursor,
    observable_type,
    value,
    first_seen,
    last_seen,
):
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


def save_relationship(
    cursor,
    indicator_id,
    observable_id,
    relationship_type,
):
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
            relationship_type,
        ),
    )


def correlate_url_indicator(
    cursor,
    indicator_id,
    url,
    first_seen,
    last_seen,
):
    extracted = extract_url_host(url)

    host = extracted["host"]
    host_type = extracted["host_type"]

    if not host or not host_type:
        return False

    observable_id = save_observable(
        cursor,
        host_type,
        host,
        first_seen,
        last_seen,
    )

    save_relationship(
        cursor,
        indicator_id,
        observable_id,
        EXTRACTED_HOST_RELATIONSHIP,
    )

    return True