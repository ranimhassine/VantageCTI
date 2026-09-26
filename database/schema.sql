-- CTI Platform
-- PostgreSQL database schema
--
-- This file defines the current baseline schema required by the
-- CTI Platform backend.
--
-- Database creation and application-user creation are intentionally
-- kept outside this file because credentials and environment-specific
-- configuration must not be stored in the repository.


-- ============================================================
-- CISA Known Exploited Vulnerabilities
-- ============================================================

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) UNIQUE NOT NULL,
    vendor VARCHAR(255),
    product VARCHAR(255),
    name TEXT,
    description TEXT,
    date_added DATE,
    source VARCHAR(100)
);


-- ============================================================
-- Threat Indicators
-- ============================================================

CREATE TABLE IF NOT EXISTS indicators (
    id SERIAL PRIMARY KEY,

    type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,

    status VARCHAR(50),
    threat_type VARCHAR(100),

    -- Preserves the original source-supplied value.
    -- Some sources, such as URLhaus, may provide multiple
    -- comma-separated tags in this field.
    malware_family VARCHAR(255),

    -- Normalized individual source tags.
    tags TEXT[] NOT NULL DEFAULT '{}',

    first_seen TIMESTAMP,
    last_seen TIMESTAMP,

    source VARCHAR(100) NOT NULL,
    source_id VARCHAR(255),
    source_reference TEXT,

    CONSTRAINT indicators_source_unique
        UNIQUE (source, source_id)
);


-- ============================================================
-- MITRE ATT&CK Enterprise Techniques
-- ============================================================

CREATE TABLE IF NOT EXISTS attack_techniques (
    id SERIAL PRIMARY KEY,

    attack_id VARCHAR(30) UNIQUE NOT NULL,
    stix_id VARCHAR(100) UNIQUE NOT NULL,

    name TEXT NOT NULL,
    description TEXT,

    tactics TEXT[],
    platforms TEXT[],

    is_subtechnique BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    deprecated BOOLEAN NOT NULL DEFAULT FALSE,

    created TIMESTAMPTZ,
    modified TIMESTAMPTZ,

    source VARCHAR(100) NOT NULL,
    source_reference TEXT
);


-- ============================================================
-- Correlated Observables
-- ============================================================
--
-- Observables represent reusable normalized CTI entities such as
-- IP addresses and domains. Multiple indicators can reference the
-- same observable instead of duplicating infrastructure context.

CREATE TABLE IF NOT EXISTS observables (
    id SERIAL PRIMARY KEY,

    type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,

    first_seen TIMESTAMP,
    last_seen TIMESTAMP,

    CONSTRAINT observables_type_value_unique
        UNIQUE (type, value)
);


-- ============================================================
-- Indicator-to-Observable Relationships
-- ============================================================
--
-- Connects source indicators to normalized observables.
-- Example:
--
-- URL indicator
--     -> extracted_host
--     -> IP/domain observable

CREATE TABLE IF NOT EXISTS indicator_observables (
    id SERIAL PRIMARY KEY,

    indicator_id INTEGER NOT NULL,
    observable_id INTEGER NOT NULL,
    relationship_type VARCHAR(100) NOT NULL,

    CONSTRAINT indicator_observables_indicator_fk
        FOREIGN KEY (indicator_id)
        REFERENCES indicators(id)
        ON DELETE CASCADE,

    CONSTRAINT indicator_observables_observable_fk
        FOREIGN KEY (observable_id)
        REFERENCES observables(id)
        ON DELETE CASCADE,

    CONSTRAINT indicator_observables_unique
        UNIQUE (
            indicator_id,
            observable_id,
            relationship_type
        )
);


-- ============================================================
-- Application Role Permissions
-- ============================================================
--
-- The role itself and its password are not created here.
-- Create the cti_app role separately and provide its credentials
-- through the local .env file.

GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE vulnerabilities
TO cti_app;

GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE indicators
TO cti_app;

GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE attack_techniques
TO cti_app;

GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE observables
TO cti_app;

GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE indicator_observables
TO cti_app;


GRANT USAGE, SELECT
ON SEQUENCE vulnerabilities_id_seq
TO cti_app;

GRANT USAGE, SELECT
ON SEQUENCE indicators_id_seq
TO cti_app;

GRANT USAGE, SELECT
ON SEQUENCE attack_techniques_id_seq
TO cti_app;

GRANT USAGE, SELECT
ON SEQUENCE observables_id_seq
TO cti_app;

GRANT USAGE, SELECT
ON SEQUENCE indicator_observables_id_seq
TO cti_app;