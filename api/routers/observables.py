from fastapi import APIRouter, HTTPException, Query

from database.connection import get_connection


router = APIRouter(
    prefix="/api/v1/observables",
    tags=["Observables"],
)


def get_count_summary(
    cursor,
    observable_id,
    column_name,
):
    allowed_columns = {
        "status",
        "threat_type",
        "source",
    }

    if column_name not in allowed_columns:
        raise ValueError(
            f"Unsupported summary column: {column_name}"
        )

    cursor.execute(
        f"""
        SELECT
            i.{column_name},
            COUNT(*) AS indicator_count
        FROM indicator_observables io
        JOIN indicators i
            ON i.id = io.indicator_id
        WHERE
            io.observable_id = %s
            AND i.{column_name} IS NOT NULL
            AND i.{column_name} <> ''
        GROUP BY i.{column_name}
        ORDER BY
            indicator_count DESC,
            i.{column_name};
        """,
        (observable_id,),
    )

    rows = cursor.fetchall()

    return [
        {
            "name": row[0],
            "count": row[1],
        }
        for row in rows
    ]


def get_tag_summary(
    cursor,
    observable_id,
):
    cursor.execute(
        """
        SELECT
            tag_name,
            COUNT(*) AS indicator_count
        FROM indicator_observables io
        JOIN indicators i
            ON i.id = io.indicator_id
        CROSS JOIN LATERAL unnest(i.tags) AS tag_name
        WHERE io.observable_id = %s
        GROUP BY tag_name
        ORDER BY
            indicator_count DESC,
            tag_name;
        """,
        (observable_id,),
    )

    rows = cursor.fetchall()

    return [
        {
            "name": row[0],
            "count": row[1],
        }
        for row in rows
    ]


def get_intelligence_summary(
    cursor,
    observable_id,
):
    return {
        "statuses": get_count_summary(
            cursor,
            observable_id,
            "status",
        ),
        "threat_types": get_count_summary(
            cursor,
            observable_id,
            "threat_type",
        ),
        "sources": get_count_summary(
            cursor,
            observable_id,
            "source",
        ),
        "tags": get_tag_summary(
            cursor,
            observable_id,
        ),
    }


def get_enrichments(
    cursor,
    observable_id,
):
    cursor.execute(
        """
        SELECT
            provider,
            asn,
            as_name,
            as_domain,
            country_code,
            country,
            continent_code,
            continent,
            retrieved_at
        FROM observable_enrichments
        WHERE observable_id = %s
        ORDER BY provider;
        """,
        (observable_id,),
    )

    rows = cursor.fetchall()

    return [
        {
            "provider": row[0],
            "asn": row[1],
            "as_name": row[2],
            "as_domain": row[3],
            "country_code": row[4],
            "country": row[5],
            "continent_code": row[6],
            "continent": row[7],
            "retrieved_at": row[8],
        }
        for row in rows
    ]


@router.get("")
def get_observables(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    observable_type: str | None = Query(default=None),
    search: str | None = Query(default=None),
    country: str | None = Query(default=None),
    asn: str | None = Query(default=None),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        conditions = []
        parameters = []

        if observable_type:
            conditions.append(
                "LOWER(o.type) = LOWER(%s)"
            )
            parameters.append(observable_type)

        if search:
            conditions.append(
                "LOWER(o.value) LIKE LOWER(%s)"
            )
            parameters.append(f"%{search}%")

        if country:
            conditions.append(
                """
                EXISTS (
                    SELECT 1
                    FROM observable_enrichments oe_filter
                    WHERE
                        oe_filter.observable_id = o.id
                        AND LOWER(oe_filter.country)
                            = LOWER(%s)
                )
                """
            )
            parameters.append(country)

        if asn:
            conditions.append(
                """
                EXISTS (
                    SELECT 1
                    FROM observable_enrichments oe_filter
                    WHERE
                        oe_filter.observable_id = o.id
                        AND LOWER(oe_filter.asn)
                            = LOWER(%s)
                )
                """
            )
            parameters.append(asn)

        where_clause = ""

        if conditions:
            where_clause = (
                "WHERE "
                + " AND ".join(conditions)
            )

        cursor.execute(
            f"""
            SELECT COUNT(*)
            FROM observables o
            {where_clause};
            """,
            parameters,
        )

        total = cursor.fetchone()[0]

        cursor.execute(
            f"""
            SELECT
                o.id,
                o.type,
                o.value,
                o.first_seen,
                o.last_seen,
                COUNT(DISTINCT io.indicator_id)
                    AS related_indicator_count,
                MAX(oe.provider) AS provider,
                MAX(oe.asn) AS asn,
                MAX(oe.as_name) AS as_name,
                MAX(oe.country_code) AS country_code,
                MAX(oe.country) AS country
            FROM observables o
            LEFT JOIN indicator_observables io
                ON io.observable_id = o.id
            LEFT JOIN observable_enrichments oe
                ON oe.observable_id = o.id
                AND oe.provider = 'IPinfo'
            {where_clause}
            GROUP BY
                o.id,
                o.type,
                o.value,
                o.first_seen,
                o.last_seen
            ORDER BY
                related_indicator_count DESC,
                o.last_seen DESC NULLS LAST,
                o.id DESC
            LIMIT %s
            OFFSET %s;
            """,
            parameters + [limit, offset],
        )

        rows = cursor.fetchall()

        observables = []

        for row in rows:
            observables.append(
                {
                    "id": row[0],
                    "type": row[1],
                    "value": row[2],
                    "first_seen": row[3],
                    "last_seen": row[4],
                    "related_indicator_count": row[5],
                    "enrichment": (
                        {
                            "provider": row[6],
                            "asn": row[7],
                            "as_name": row[8],
                            "country_code": row[9],
                            "country": row[10],
                        }
                        if row[6]
                        else None
                    ),
                }
            )

        return {
            "total": total,
            "returned": len(observables),
            "limit": limit,
            "offset": offset,
            "filters": {
                "type": observable_type,
                "search": search,
                "country": country,
                "asn": asn,
            },
            "observables": observables,
        }

    finally:
        cursor.close()
        connection.close()


@router.get("/lookup")
def lookup_observable(
    value: str = Query(..., min_length=1),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
                type,
                value,
                first_seen,
                last_seen
            FROM observables
            WHERE LOWER(value) = LOWER(%s)
            ORDER BY type;
            """,
            (value,),
        )

        rows = cursor.fetchall()

        if not rows:
            raise HTTPException(
                status_code=404,
                detail=f"Observable not found: {value}",
            )

        observables = []

        for row in rows:
            observable_id = row[0]

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM indicator_observables
                WHERE observable_id = %s;
                """,
                (observable_id,),
            )

            related_indicator_count = cursor.fetchone()[0]

            intelligence_summary = get_intelligence_summary(
                cursor,
                observable_id,
            )

            enrichments = get_enrichments(
                cursor,
                observable_id,
            )

            cursor.execute(
                """
                SELECT
                    i.id,
                    i.type,
                    i.value,
                    i.status,
                    i.threat_type,
                    i.malware_family,
                    i.tags,
                    i.first_seen,
                    i.last_seen,
                    i.source,
                    i.source_id,
                    i.source_reference,
                    io.relationship_type
                FROM indicator_observables io
                JOIN indicators i
                    ON i.id = io.indicator_id
                WHERE io.observable_id = %s
                ORDER BY i.first_seen DESC, i.id DESC
                LIMIT %s
                OFFSET %s;
                """,
                (
                    observable_id,
                    limit,
                    offset,
                ),
            )

            indicator_rows = cursor.fetchall()

            related_indicators = []

            for indicator_row in indicator_rows:
                related_indicators.append(
                    {
                        "id": indicator_row[0],
                        "type": indicator_row[1],
                        "value": indicator_row[2],
                        "status": indicator_row[3],
                        "threat_type": indicator_row[4],
                        "malware_family": indicator_row[5],
                        "tags": indicator_row[6],
                        "first_seen": indicator_row[7],
                        "last_seen": indicator_row[8],
                        "source": indicator_row[9],
                        "source_id": indicator_row[10],
                        "source_reference": indicator_row[11],
                        "relationship_type": indicator_row[12],
                    }
                )

            observables.append(
                {
                    "id": row[0],
                    "type": row[1],
                    "value": row[2],
                    "first_seen": row[3],
                    "last_seen": row[4],
                    "related_indicator_count": (
                        related_indicator_count
                    ),
                    "intelligence_summary": intelligence_summary,
                    "enrichments": enrichments,
                    "returned": len(related_indicators),
                    "limit": limit,
                    "offset": offset,
                    "related_indicators": related_indicators,
                }
            )

        return {
            "query": value,
            "matches": len(observables),
            "observables": observables,
        }

    finally:
        cursor.close()
        connection.close()