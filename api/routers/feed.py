from fastapi import APIRouter, Query

from database.connection import get_connection


router = APIRouter(
    prefix="/api/v1/feed",
    tags=["Intelligence Feed"],
)


@router.get("")
def get_intelligence_feed(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None),
    source: str | None = Query(default=None),
    feed_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        conditions = []
        parameters = []

        if search:
            conditions.append(
                """
                (
                    LOWER(COALESCE(title, ''))
                        LIKE LOWER(%s)
                    OR LOWER(COALESCE(summary, ''))
                        LIKE LOWER(%s)
                    OR LOWER(COALESCE(observable, ''))
                        LIKE LOWER(%s)
                    OR LOWER(COALESCE(source_id, ''))
                        LIKE LOWER(%s)
                )
                """
            )

            search_value = f"%{search}%"

            parameters.extend(
                [
                    search_value,
                    search_value,
                    search_value,
                    search_value,
                ]
            )

        if source:
            conditions.append(
                "LOWER(source) = LOWER(%s)"
            )
            parameters.append(source)

        if feed_type:
            conditions.append(
                "LOWER(feed_type) = LOWER(%s)"
            )
            parameters.append(feed_type)

        if status:
            conditions.append(
                "LOWER(COALESCE(status, '')) = LOWER(%s)"
            )
            parameters.append(status)

        where_clause = ""

        if conditions:
            where_clause = (
                "WHERE "
                + " AND ".join(conditions)
            )

        unified_feed_query = """
            SELECT
                'vulnerability' AS feed_type,
                source,
                cve_id AS source_id,
                cve_id || ' - ' || name AS title,
                description AS summary,
                date_added::timestamp AS event_time,
                NULL::text AS status,
                'known_exploited_vulnerability'::text
                    AS threat_type,
                NULL::text AS malware_family,
                cve_id AS observable,
                NULL::text AS source_reference
            FROM vulnerabilities

            UNION ALL

            SELECT
                'indicator' AS feed_type,
                source,
                source_id,
                COALESCE(
                    threat_type || ' - ' || value,
                    value
                ) AS title,
                NULL::text AS summary,
                first_seen AS event_time,
                status,
                threat_type,
                malware_family,
                value AS observable,
                source_reference
            FROM indicators
        """

        cursor.execute(
            f"""
            SELECT COUNT(*)
            FROM (
                {unified_feed_query}
            ) AS unified_feed
            {where_clause};
            """,
            parameters,
        )

        total = cursor.fetchone()[0]

        cursor.execute(
            f"""
            SELECT
                feed_type,
                source,
                source_id,
                title,
                summary,
                event_time,
                status,
                threat_type,
                malware_family,
                observable,
                source_reference
            FROM (
                {unified_feed_query}
            ) AS unified_feed
            {where_clause}
            ORDER BY
                event_time DESC,
                source,
                source_id
            LIMIT %s
            OFFSET %s;
            """,
            parameters + [limit, offset],
        )

        rows = cursor.fetchall()

        feed_items = []

        for row in rows:
            feed_items.append(
                {
                    "type": row[0],
                    "source": row[1],
                    "source_id": row[2],
                    "title": row[3],
                    "summary": row[4],
                    "timestamp": row[5],
                    "status": row[6],
                    "threat_type": row[7],
                    "malware_family": row[8],
                    "observable": row[9],
                    "source_reference": row[10],
                }
            )

        return {
            "total": total,
            "returned": len(feed_items),
            "limit": limit,
            "offset": offset,
            "filters": {
                "search": search,
                "source": source,
                "type": feed_type,
                "status": status,
            },
            "items": feed_items,
        }

    finally:
        cursor.close()
        connection.close()