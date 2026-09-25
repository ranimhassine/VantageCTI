import csv
import io
import os

import requests
from dotenv import load_dotenv


load_dotenv()


URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def get_urlhaus_recent():
    auth_key = os.getenv("URLHAUS_AUTH_KEY")

    if not auth_key:
        raise RuntimeError(
            "URLHAUS_AUTH_KEY is missing from the .env file."
        )

    headers = {
        "Auth-Key": auth_key,
    }

    response = requests.get(
        URLHAUS_RECENT_URL,
        headers=headers,
        timeout=30,
    )

    response.raise_for_status()

    return response.text


def parse_urlhaus_csv(csv_data):
    data_lines = []

    for line in csv_data.splitlines():
        if not line.startswith("#") and line.strip():
            data_lines.append(line)

    clean_csv = "\n".join(data_lines)
    reader = csv.reader(io.StringIO(clean_csv))

    return list(reader)


def clean_optional_value(value):
    if value is None:
        return None

    value = value.strip()

    if not value or value.lower() == "none":
        return None

    return value


def normalize_urlhaus_record(record):
    return {
        "type": "url",
        "value": record[2].strip(),
        "status": clean_optional_value(record[3]),
        "threat_type": clean_optional_value(record[5]),
        "malware_family": clean_optional_value(record[6]),
        "first_seen": clean_optional_value(record[1]),
        "last_seen": clean_optional_value(record[4]),
        "source": "URLhaus",
        "source_id": record[0].strip(),
        "source_reference": clean_optional_value(record[7]),
    }


if __name__ == "__main__":
    csv_data = get_urlhaus_recent()
    records = parse_urlhaus_csv(csv_data)

    print("Actual URLhaus records:", len(records))

    if records:
        normalized = normalize_urlhaus_record(records[0])

        print("\nNormalized first indicator:")

        for key, value in normalized.items():
            print(f"{key}: {value}")