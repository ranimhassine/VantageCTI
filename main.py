from fastapi import FastAPI, HTTPException, Query

from api.routers.dashboard import router as dashboard_router
from api.routers.feed import router as feed_router
from api.routers.indicators import router as indicators_router
from api.routers.vulnerabilities import router as vulnerabilities_router
from database.connection import get_connection


app = FastAPI(
    title="CTI Platform API",
    description="Vendor-neutral Cyber Threat Intelligence Platform",
    version="0.1.0",
)

app.include_router(dashboard_router)
app.include_router(feed_router)
app.include_router(vulnerabilities_router)
app.include_router(indicators_router)


@app.get("/")
def home():
    return {
        "message": "CTI Platform is running",
        "version": "0.1.0",
    }


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