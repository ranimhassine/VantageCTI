import ipaddress
import re
from urllib.parse import urlparse

from fastapi import APIRouter, Query

from database.connection import get_connection


router = APIRouter(
    prefix="/api/v1/investigate",
    tags=["Investigation"],
)


CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE,
)

ATTACK_PATTERN = re.compile(
    r"^T\d{4}(?:\.\d{3})?$",
    re.IGNORECASE,
)


def classify_query(value):
    cleaned_value = value.strip()

    if CVE_PATTERN.match(cleaned_value):
        return "cve"

    if ATTACK_PATTERN.match(cleaned_value):
        return "attack_technique"

    try:
        ipaddress.ip_address(cleaned_value)
        return "ip"
    except ValueError:
        pass

    try:
        parsed = urlparse(cleaned_value)

        if (
            parsed.scheme in {"http", "https"}
            and parsed.hostname
        ):
            return "url"
    except ValueError:
        pass

    return "domain_or_text"


def serialize_indicator(row):
    return {
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


def find_observables(
    cursor,
    value,
):
    cursor.execute(
        """
        SELECT
            id,
            type,
            value,
            first_seen,
            last_seen
        FROM observables
        WHERE LOWER(value) = LOWER(%s)
        ORDER BY type;
        """,
        (value,),
    )

    rows = cursor.fetchall()

    results = []

    for row in rows:
        observable_id = row[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM indicator_observables
            WHERE observable_id = %s;
            """,
            (observable_id,),
        )

        related_indicator_count = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT
                provider,
                asn,
                as_name,
                as_domain,
                country_code,
                country,
                continent_code,
                continent,
                retrieved_at
            FROM observable_enrichments
            WHERE observable_id = %s
            ORDER BY provider;
            """,
            (observable_id,),
        )

        enrichment_rows = cursor.fetchall()

        enrichments = []

        for enrichment_row in enrichment_rows:
            enrichments.append(
                {
                    "provider": enrichment_row[0],
                    "asn": enrichment_row[1],
                    "as_name": enrichment_row[2],
                    "as_domain": enrichment_row[3],
                    "country_code": enrichment_row[4],
                    "country": enrichment_row[5],
                    "continent_code": enrichment_row[6],
                    "continent": enrichment_row[7],
                    "retrieved_at": enrichment_row[8],
                }
            )

        results.append(
            {
                "id": row[0],
                "type": row[1],
                "value": row[2],
                "first_seen": row[3],
                "last_seen": row[4],
                "related_indicator_count": (
                    related_indicator_count
                ),
                "enrichments": enrichments,
            }
        )

    return results


def find_indicators(
    cursor,
    value,
    limit,
):
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
        ORDER BY first_seen DESC, id DESC
        LIMIT %s;
        """,
        (
            value,
            limit,
        ),
    )

    return [
        serialize_indicator(row)
        for row in cursor.fetchall()
    ]


def find_vulnerability(
    cursor,
    value,
):
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
        (value,),
    )

    row = cursor.fetchone()

    if row is None:
        return None

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


def find_attack_technique(
    cursor,
    value,
):
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
        (value,),
    )

    row = cursor.fetchone()

    if row is None:
        return None

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


@router.get("")
def investigate(
    q: str = Query(..., min_length=1),
    limit: int = Query(default=10, ge=1, le=100),
):
    query = q.strip()
    detected_type = classify_query(query)

    connection = get_connection()
    cursor = connection.cursor()

    try:
        observables = []
        indicators = []
        vulnerability = None
        attack_technique = None

        if detected_type in {
            "ip",
            "domain_or_text",
        }:
            observables = find_observables(
                cursor,
                query,
            )

        if detected_type == "url":
            indicators = find_indicators(
                cursor,
                query,
                limit,
            )

        if detected_type == "cve":
            vulnerability = find_vulnerability(
                cursor,
                query,
            )

        if detected_type == "attack_technique":
            attack_technique = find_attack_technique(
                cursor,
                query,
            )

        result_count = (
            len(observables)
            + len(indicators)
            + (1 if vulnerability else 0)
            + (1 if attack_technique else 0)
        )

        return {
            "query": query,
            "detected_type": detected_type,
            "found": result_count > 0,
            "result_count": result_count,
            "results": {
                "observables": observables,
                "indicators": indicators,
                "vulnerability": vulnerability,
                "attack_technique": attack_technique,
            },
        }

    finally:
        cursor.close()
        connection.close()