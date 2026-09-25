from fastapi import APIRouter

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
                ) AS active_attack_techniques;
            """
        )

        row = cursor.fetchone()

        return {
            "vulnerabilities": row[0],
            "indicators": row[1],
            "online_indicators": row[2],
            "active_attack_techniques": row[3],
            "sources": {
                "cisa_kev": True,
                "urlhaus": True,
                "mitre_attack": True,
            },
        }

    finally:
        cursor.close()
        connection.close()