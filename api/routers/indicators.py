from fastapi import APIRouter, HTTPException, Query

from database.connection import get_connection


router = APIRouter(
    prefix="/api/v1/indicators",
    tags=["Indicators"],
)


@router.get("/lookup")
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
                tags,
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
                    "tags": row[6],
                    "first_seen": row[7],
                    "last_seen": row[8],
                    "source": row[9],
                    "source_id": row[10],
                    "source_reference": row[11],
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


@router.get("")
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
                tags,
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
                    "tags": row[6],
                    "first_seen": row[7],
                    "last_seen": row[8],
                    "source": row[9],
                    "source_id": row[10],
                    "source_reference": row[11],
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