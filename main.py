from fastapi import FastAPI, HTTPException, Query

from database.connection import get_connection


app = FastAPI(
    title="CTI Platform API",
    description="Vendor-neutral Cyber Threat Intelligence Platform",
    version="0.1.0",
)


@app.get("/")
def home():
    return {
        "message": "CTI Platform is running",
        "version": "0.1.0",
    }


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