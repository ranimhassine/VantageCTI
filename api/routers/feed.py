from fastapi import APIRouter, Query

from database.connection import get_connection


router = APIRouter(
    prefix="/api/v1/feed",
    tags=["Intelligence Feed"],
)


@router.get("")
def get_intelligence_feed(
    limit: int = Query(default=20, ge=1, le=100),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
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
            ) AS unified_feed
            ORDER BY event_time DESC, source, source_id
            LIMIT %s;
            """,
            (limit,),
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
            "returned": len(feed_items),
            "items": feed_items,
        }

    finally:
        cursor.close()
        connection.close()