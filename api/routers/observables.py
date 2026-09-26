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