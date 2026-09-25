from fastapi import FastAPI, HTTPException, Query

from api.routers.dashboard import router as dashboard_router
from database.connection import get_connection


app = FastAPI(
    title="CTI Platform API",
    description="Vendor-neutral Cyber Threat Intelligence Platform",
    version="0.1.0",
)

app.include_router(dashboard_router)


@app.get("/")
def home():
    return {
        "message": "CTI Platform is running",
        "version": "0.1.0",
    }


@app.get("/api/v1/feed")
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


@app.get("/api/v1/vulnerabilities")
def get_vulnerabilities(
    limit: int = Query(default=10, ge=1, le=100),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities;")
        total = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT
                id,
                cve_id,
                vendor,
                product,
                name,
                description,
                date_added,
                source
            FROM vulnerabilities
            ORDER BY date_added DESC, cve_id
            LIMIT %s;
            """,
            (limit,),
        )

        rows = cursor.fetchall()

        vulnerabilities = []

        for row in rows:
            vulnerabilities.append(
                {
                    "id": row[0],
                    "cve_id": row[1],
                    "vendor": row[2],
                    "product": row[3],
                    "name": row[4],
                    "description": row[5],
                    "date_added": row[6],
                    "source": row[7],
                }
            )

        return {
            "total": total,
            "returned": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }

    finally:
        cursor.close()
        connection.close()


@app.get("/api/v1/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
                cve_id,
                vendor,
                product,
                name,
                description,
                date_added,
                source
            FROM vulnerabilities
            WHERE UPPER(cve_id) = UPPER(%s);
            """,
            (cve_id,),
        )

        row = cursor.fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail=f"Vulnerability {cve_id} not found",
            )

        return {
            "id": row[0],
            "cve_id": row[1],
            "vendor": row[2],
            "product": row[3],
            "name": row[4],
            "description": row[5],
            "date_added": row[6],
            "source": row[7],
        }

    finally:
        cursor.close()
        connection.close()


@app.get("/api/v1/indicators/lookup")
def lookup_indicator(
    value: str = Query(..., min_length=1),
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
                status,
                threat_type,
                malware_family,
                first_seen,
                last_seen,
                source,
                source_id,
                source_reference
            FROM indicators
            WHERE value = %s
            ORDER BY source, source_id;
            """,
            (value,),
        )

        rows = cursor.fetchall()

        if not rows:
            raise HTTPException(
                status_code=404,
                detail=f"Indicator not found: {value}",
            )

        indicators = []

        for row in rows:
            indicators.append(
                {
                    "id": row[0],
                    "type": row[1],
                    "value": row[2],
                    "status": row[3],
                    "threat_type": row[4],
                    "malware_family": row[5],
                    "first_seen": row[6],
                    "last_seen": row[7],
                    "source": row[8],
                    "source_id": row[9],
                    "source_reference": row[10],
                }
            )

        return {
            "value": value,
            "matches": len(indicators),
            "indicators": indicators,
        }

    finally:
        cursor.close()
        connection.close()


@app.get("/api/v1/indicators")
def get_indicators(
    limit: int = Query(default=10, ge=1, le=100),
    status: str | None = Query(default=None),
    malware_family: str | None = Query(default=None),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        conditions = []
        parameters = []

        if status:
            conditions.append("LOWER(status) = LOWER(%s)")
            parameters.append(status)

        if malware_family:
            conditions.append("LOWER(malware_family) LIKE LOWER(%s)")
            parameters.append(f"%{malware_family}%")

        where_clause = ""

        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        cursor.execute(
            f"""
            SELECT COUNT(*)
            FROM indicators
            {where_clause};
            """,
            parameters,
        )

        total = cursor.fetchone()[0]

        cursor.execute(
            f"""
            SELECT
                id,
                type,
                value,
                status,
                threat_type,
                malware_family,
                first_seen,
                last_seen,
                source,
                source_id,
                source_reference
            FROM indicators
            {where_clause}
            ORDER BY first_seen DESC, id DESC
            LIMIT %s;
            """,
            parameters + [limit],
        )

        rows = cursor.fetchall()

        indicators = []

        for row in rows:
            indicators.append(
                {
                    "id": row[0],
                    "type": row[1],
                    "value": row[2],
                    "status": row[3],
                    "threat_type": row[4],
                    "malware_family": row[5],
                    "first_seen": row[6],
                    "last_seen": row[7],
                    "source": row[8],
                    "source_id": row[9],
                    "source_reference": row[10],
                }
            )

        return {
            "total": total,
            "returned": len(indicators),
            "filters": {
                "status": status,
                "malware_family": malware_family,
            },
            "indicators": indicators,
        }

    finally:
        cursor.close()
        connection.close()


@app.get("/api/v1/attack/techniques")
def get_attack_techniques(
    limit: int = Query(default=10, ge=1, le=100),
    tactic: str | None = Query(default=None),
    platform: str | None = Query(default=None),
    is_subtechnique: bool | None = Query(default=None),
):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        conditions = [
            "revoked = FALSE",
            "deprecated = FALSE",
        ]
        parameters = []

        if tactic:
            conditions.append(
                """
                EXISTS (
                    SELECT 1
                    FROM unnest(tactics) AS tactic_name
                    WHERE LOWER(tactic_name) = LOWER(%s)
                )
                """
            )
            parameters.append(tactic)

        if platform:
            conditions.append(
                """
                EXISTS (
                    SELECT 1
                    FROM unnest(platforms) AS platform_name
                    WHERE LOWER(platform_name) = LOWER(%s)
                )
                """
            )
            parameters.append(platform)

        if is_subtechnique is not None:
            conditions.append("is_subtechnique = %s")
            parameters.append(is_subtechnique)

        where_clause = "WHERE " + " AND ".join(conditions)

        cursor.execute(
            f"""
            SELECT COUNT(*)
            FROM attack_techniques
            {where_clause};
            """,
            parameters,
        )

        total = cursor.fetchone()[0]

        cursor.execute(
            f"""
            SELECT
                id,
                attack_id,
                stix_id,
                name,
                description,
                tactics,
                platforms,
                is_subtechnique,
                revoked,
                deprecated,
                created,
                modified,
                source,
                source_reference
            FROM attack_techniques
            {where_clause}
            ORDER BY attack_id
            LIMIT %s;
            """,
            parameters + [limit],
        )

        rows = cursor.fetchall()

        techniques = []

        for row in rows:
            techniques.append(
                {
                    "id": row[0],
                    "attack_id": row[1],
                    "stix_id": row[2],
                    "name": row[3],
                    "description": row[4],
                    "tactics": row[5],
                    "platforms": row[6],
                    "is_subtechnique": row[7],
                    "revoked": row[8],
                    "deprecated": row[9],
                    "created": row[10],
                    "modified": row[11],
                    "source": row[12],
                    "source_reference": row[13],
                }
            )

        return {
            "total": total,
            "returned": len(techniques),
            "filters": {
                "tactic": tactic,
                "platform": platform,
                "is_subtechnique": is_subtechnique,
            },
            "techniques": techniques,
        }

    finally:
        cursor.close()
        connection.close()


@app.get("/api/v1/attack/techniques/{attack_id}")
def get_attack_technique(attack_id: str):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
                attack_id,
                stix_id,
                name,
                description,
                tactics,
                platforms,
                is_subtechnique,
                revoked,
                deprecated,
                created,
                modified,
                source,
                source_reference
            FROM attack_techniques
            WHERE UPPER(attack_id) = UPPER(%s);
            """,
            (attack_id,),
        )

        row = cursor.fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail=f"ATT&CK technique {attack_id} not found",
            )

        return {
            "id": row[0],
            "attack_id": row[1],
            "stix_id": row[2],
            "name": row[3],
            "description": row[4],
            "tactics": row[5],
            "platforms": row[6],
            "is_subtechnique": row[7],
            "revoked": row[8],
            "deprecated": row[9],
            "created": row[10],
            "modified": row[11],
            "source": row[12],
            "source_reference": row[13],
        }

    finally:
        cursor.close()
        connection.close()