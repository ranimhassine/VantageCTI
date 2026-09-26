from fastapi import APIRouter, Query

from database.connection import get_connection


router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["Dashboard"],
)


@router.get("/summary")
def get_dashboard_summary():
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM vulnerabilities)
                    AS vulnerabilities,
                (SELECT COUNT(*) FROM indicators)
                    AS indicators,
                (
                    SELECT COUNT(*)
                    FROM indicators
                    WHERE LOWER(status) = 'online'
                ) AS online_indicators,
                (
                    SELECT COUNT(*)
                    FROM attack_techniques
                    WHERE revoked = FALSE
                      AND deprecated = FALSE
                ) AS active_attack_techniques,
                (SELECT COUNT(*) FROM observables)
                    AS observables,
                (
                    SELECT COUNT(*)
                    FROM observables
                    WHERE type = 'ip'
                ) AS ip_observables,
                (
                    SELECT COUNT(*)
                    FROM observables
                    WHERE type = 'domain'
                ) AS domain_observables,
                (
                    SELECT COUNT(*)
                    FROM observable_enrichments
                    WHERE provider = 'IPinfo'
                ) AS enriched_ips;
            """
        )

        row = cursor.fetchone()

        return {
            "vulnerabilities": row[0],
            "indicators": row[1],
            "online_indicators": row[2],
            "active_attack_techniques": row[3],
            "observables": row[4],
            "ip_observables": row[5],
            "domain_observables": row[6],
            "enriched_ips": row[7],
            "sources": {
                "cisa_kev": True,
                "urlhaus": True,
                "mitre_attack": True,
                "ipinfo": True,
            },
        }

    finally:
        cursor.close()
        connection.close()


@router.get("/intelligence")
def get_dashboard_intelligence(
    limit: int = Query(default=10, ge=1, le=25),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                type,
                COUNT(*) AS observable_count
            FROM observables
            GROUP BY type
            ORDER BY observable_count DESC, type;
            """
        )

        observable_types = [
            {
                "type": row[0],
                "count": row[1],
            }
            for row in cursor.fetchall()
        ]

        cursor.execute(
            """
            SELECT
                tag_name,
                COUNT(*) AS indicator_count
            FROM indicators
            CROSS JOIN LATERAL unnest(tags) AS tag_name
            WHERE tag_name IS NOT NULL
              AND tag_name <> ''
            GROUP BY tag_name
            ORDER BY indicator_count DESC, tag_name
            LIMIT %s;
            """,
            (limit,),
        )

        top_tags = [
            {
                "name": row[0],
                "count": row[1],
            }
            for row in cursor.fetchall()
        ]

        cursor.execute(
            """
            SELECT
                country_code,
                country,
                COUNT(*) AS ip_count
            FROM observable_enrichments
            WHERE provider = 'IPinfo'
              AND country IS NOT NULL
              AND country <> ''
            GROUP BY country_code, country
            ORDER BY ip_count DESC, country
            LIMIT %s;
            """,
            (limit,),
        )

        top_countries = [
            {
                "country_code": row[0],
                "country": row[1],
                "count": row[2],
            }
            for row in cursor.fetchall()
        ]

        cursor.execute(
            """
            SELECT
                asn,
                as_name,
                as_domain,
                COUNT(*) AS ip_count
            FROM observable_enrichments
            WHERE provider = 'IPinfo'
              AND asn IS NOT NULL
              AND asn <> ''
            GROUP BY
                asn,
                as_name,
                as_domain
            ORDER BY ip_count DESC, asn
            LIMIT %s;
            """,
            (limit,),
        )

        top_asns = [
            {
                "asn": row[0],
                "name": row[1],
                "domain": row[2],
                "count": row[3],
            }
            for row in cursor.fetchall()
        ]

        cursor.execute(
            """
            SELECT
                COALESCE(status, 'unknown') AS status_name,
                COUNT(*) AS indicator_count
            FROM indicators
            GROUP BY COALESCE(status, 'unknown')
            ORDER BY indicator_count DESC, status_name;
            """
        )

        indicator_statuses = [
            {
                "status": row[0],
                "count": row[1],
            }
            for row in cursor.fetchall()
        ]

        cursor.execute(
            """
            SELECT
                source,
                COUNT(*) AS item_count
            FROM (
                SELECT source
                FROM vulnerabilities

                UNION ALL

                SELECT source
                FROM indicators

                UNION ALL

                SELECT source
                FROM attack_techniques
                WHERE revoked = FALSE
                  AND deprecated = FALSE
            ) AS intelligence_sources
            GROUP BY source
            ORDER BY item_count DESC, source;
            """
        )

        source_distribution = [
            {
                "source": row[0],
                "count": row[1],
            }
            for row in cursor.fetchall()
        ]

        cursor.execute(
            """
            SELECT
                DATE(first_seen) AS activity_date,
                COUNT(*) AS indicator_count
            FROM indicators
            WHERE first_seen IS NOT NULL
              AND first_seen >= CURRENT_DATE - INTERVAL '13 days'
            GROUP BY DATE(first_seen)
            ORDER BY activity_date;
            """
        )

        activity_rows = cursor.fetchall()

        activity_by_date = {
            row[0]: row[1]
            for row in activity_rows
        }

        cursor.execute(
            """
            SELECT generate_series(
                CURRENT_DATE - INTERVAL '13 days',
                CURRENT_DATE,
                INTERVAL '1 day'
            )::date;
            """
        )

        recent_activity = []

        for row in cursor.fetchall():
            activity_date = row[0]

            recent_activity.append(
                {
                    "date": activity_date,
                    "count": activity_by_date.get(
                        activity_date,
                        0,
                    ),
                }
            )

        cursor.execute(
            """
            SELECT
                o.type,
                o.value,
                COUNT(io.indicator_id)
                    AS related_indicator_count
            FROM observables o
            JOIN indicator_observables io
                ON io.observable_id = o.id
            GROUP BY
                o.id,
                o.type,
                o.value
            ORDER BY
                related_indicator_count DESC,
                o.value
            LIMIT %s;
            """,
            (limit,),
        )

        most_referenced_observables = [
            {
                "type": row[0],
                "value": row[1],
                "related_indicator_count": row[2],
            }
            for row in cursor.fetchall()
        ]

        return {
            "observable_types": observable_types,
            "top_tags": top_tags,
            "top_countries": top_countries,
            "top_asns": top_asns,
            "indicator_statuses": indicator_statuses,
            "source_distribution": source_distribution,
            "recent_activity": recent_activity,
            "most_referenced_observables": (
                most_referenced_observables
            ),
            "context": {
                "country_and_asn_note": (
                    "Country and ASN values describe "
                    "infrastructure associated with observed "
                    "IP addresses. They do not imply that a "
                    "country or network is malicious."
                ),
                "observable_note": (
                    "Observable relationships are derived from "
                    "collected threat-intelligence records and "
                    "should be interpreted in source context."
                ),
            },
        }

    finally:
        cursor.close()
        connection.close()