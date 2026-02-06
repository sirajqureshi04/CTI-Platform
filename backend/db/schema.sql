
-- 1. Feeds Table: Tracks Scraper Health
CREATE TABLE IF NOT EXISTS feeds (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    enabled BOOLEAN DEFAULT TRUE,
    last_run DATETIME,
    last_success DATETIME,
    last_error TEXT,
    run_count INT DEFAULT 0,
    success_count INT DEFAULT 0,
    error_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Indicators Table: Stores Enriched IOCs
CREATE TABLE IF NOT EXISTS indicators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ioc_type VARCHAR(50) NOT NULL, -- 'ip', 'domain', 'hash'
    ioc_value VARCHAR(255) NOT NULL, -- Reduced to 255 for better indexing performance
    sources TEXT, -- Comma-separated list of source names
    confidence_score INT DEFAULT 50, -- Base confidence
    
    -- ALIGNMENT: Centralized JSON for all enrichment modules
    -- Stores: { "geo": {...}, "whois": {...}, "reputation": {...}, "ai": {...} }
    enrichment JSON, 
    
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE INDEX idx_ioc_lookup (ioc_type, ioc_value),
    INDEX idx_type (ioc_type),
    FULLTEXT idx_value_search (ioc_value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Victims Table: Ransomware Targets with AI Context
CREATE TABLE IF NOT EXISTS victims (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    group_name VARCHAR(255),
    discovered DATETIME,
    published DATETIME,
    source VARCHAR(255),
    
    -- ALIGNMENT: Stores AI-generated summaries and sector analysis
    ai_analysis JSON, 
    metadata JSON,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE INDEX idx_victim_dedup (name, group_name, published),
    INDEX idx_group (group_name),
    INDEX idx_published (published)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. CVE Specific Table: Deep Vulnerability Context
CREATE TABLE IF NOT EXISTS cve_details (
    cve_id VARCHAR(100) PRIMARY KEY, -- Matches indicator ioc_value
    is_kev BOOLEAN DEFAULT FALSE,
    vendor_project VARCHAR(255),
    product VARCHAR(255),
    vulnerability_name TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware_campaign_use VARCHAR(50),
    cvss_score DECIMAL(3,1),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    -- Note: Removed hard Foreign Key to allow independent scraping of CISA KEV
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Threat Actors / Groups
CREATE TABLE IF NOT EXISTS threat_actors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    aliases JSON, 
    first_seen DATETIME,
    last_seen DATETIME,
    attribution_reliability INT DEFAULT 1,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;