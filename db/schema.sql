-- MAVIS schema
-- Loaded automatically by the MySQL container on first start into $MYSQL_DATABASE.
-- No foreign keys from kev_entries / epss_scores to cves: KEV and EPSS can
-- reference CVEs older than the NVD polling window.

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS cves (
    cve_id         VARCHAR(20)   NOT NULL,
    published      DATETIME      NULL,
    last_modified  DATETIME      NULL,
    description    TEXT          NULL,
    cvss_score     DECIMAL(3,1)  NULL,
    cvss_severity  VARCHAR(10)   NULL,
    cvss_source    VARCHAR(50)   NULL COMMENT 'e.g. "nvd" or the CNA',
    raw_json       JSON          NULL,
    ingested_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (cve_id),
    INDEX idx_cves_published (published)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id            VARCHAR(20)   NOT NULL,
    vendor            VARCHAR(255)  NULL,
    product           VARCHAR(255)  NULL,
    date_added        DATE          NULL,
    due_date          DATE          NULL,
    known_ransomware  VARCHAR(20)   NULL,
    ingested_at       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (cve_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id      VARCHAR(20)   NOT NULL,
    score_date  DATE          NOT NULL,
    epss        DECIMAL(6,5)  NULL,
    percentile  DECIMAL(6,5)  NULL,
    PRIMARY KEY (cve_id, score_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- One row per feed fetch during `poll`, for the HUD's feed-health dots.
-- mavis/runs.py also creates this table, so existing databases don't need a reset.
CREATE TABLE IF NOT EXISTS feed_runs (
    id           INT           NOT NULL AUTO_INCREMENT,
    feed         VARCHAR(10)   NOT NULL,
    finished_at  DATETIME      NOT NULL,
    ok           BOOLEAN       NOT NULL,
    items        INT           NULL,
    error        VARCHAR(500)  NULL,
    PRIMARY KEY (id),
    INDEX idx_feed_runs_feed (feed, finished_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS digests (
    id           INT           NOT NULL AUTO_INCREMENT,
    created_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    input_hash   CHAR(64)      NULL,
    cve_ids      JSON          NULL,
    output_json  JSON          NULL,
    model        VARCHAR(50)   NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
