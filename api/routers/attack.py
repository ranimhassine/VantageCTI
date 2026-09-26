from fastapi import APIRouter, HTTPException, Query

from database.connection import get_connection


router = APIRouter(
    prefix="/api/v1/attack",
    tags=["MITRE ATT&CK"],
)


@router.get("/techniques")
def get_attack_techniques(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None),
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

        if search:
            conditions.append(
                """
                (
                    UPPER(attack_id)
                        LIKE UPPER(%s)
                    OR LOWER(name)
                        LIKE LOWER(%s)
                    OR LOWER(COALESCE(description, ''))
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
                ]
            )

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
            conditions.append(
                "is_subtechnique = %s"
            )
            parameters.append(is_subtechnique)

        where_clause = (
            "WHERE "
            + " AND ".join(conditions)
        )

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
            LIMIT %s
            OFFSET %s;
            """,
            parameters + [limit, offset],
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
            "limit": limit,
            "offset": offset,
            "filters": {
                "search": search,
                "tactic": tactic,
                "platform": platform,
                "is_subtechnique": is_subtechnique,
            },
            "techniques": techniques,
        }

    finally:
        cursor.close()
        connection.close()


@router.get("/techniques/{attack_id}")
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
                detail=(
                    f"ATT&CK technique "
                    f"{attack_id} not found"
                ),
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