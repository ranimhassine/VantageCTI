from fastapi import APIRouter, HTTPException, Query

from database.connection import get_connection


router = APIRouter(
    prefix="/api/v1/vulnerabilities",
    tags=["Vulnerabilities"],
)


@router.get("")
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


@router.get("/{cve_id}")
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