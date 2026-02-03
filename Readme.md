# CTI Platform

A production-grade Cyber Threat Intelligence (CTI) platform for automated threat intelligence collection, processing, and analysis.

## Features

- **Feed Ingestion**: Automated collection from multiple threat intelligence sources
  - Ransomware.live
  - AlienVault OTX
  - CISA KEV (Known Exploited Vulnerabilities)
  - Malpedia

- **Processing Pipeline**:
  - IOC normalization and validation
  - Deduplication
  - Relevance scoring (UAE-specific)
  - Risk scoring
  - Enrichment (GeoIP, WHOIS, reputation)
  - Intelligence generation (actor tracking, campaign tracking, CVE tracking)

- **API**: RESTful API for accessing threat intelligence
- **Alerts**: Email alerts for high-risk IOCs
- **Database**: MySQL storage for feeds, IOCs, and intelligence

## Architecture

```
Feed Ingestion → Parsing → Normalization → Deduplication → 
Relevance Scoring → Risk Scoring → Enrichment → Intelligence → Storage → API
```

## Installation

### Prerequisites

- Python 3.11+
- MySQL 8.0+
- Kali Linux (recommended)

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd CTI-Platform
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize database:
```bash
chmod +x backend/scripts/init_db.sh
./backend/scripts/init_db.sh
```

5. Configure environment variables (optional):
```bash
export DB_HOST=localhost
export DB_USER=cti_user
export DB_PASSWORD=your_password
export DB_NAME=cti_platform
export CTI_API_KEY=your_api_key
```

## Usage

### Running the Pipeline

Execute the complete CTI pipeline:

```bash
python backend/cti_pipeline.py
```

Or use the provided script:

```bash
chmod +x backend/scripts/run_pipeline.sh
./backend/scripts/run_pipeline.sh
```

### Running the API

Start the Flask API server:

```bash
python backend/api/app.py
```

The API will be available at `http://localhost:5000`

### API Endpoints

- `GET /health` - Health check
- `GET /api/v1/feeds/` - List all feeds
- `GET /api/v1/feeds/<feed_name>` - Get feed information
- `GET /api/v1/incidents/iocs` - Get IOCs (with filtering)
- `GET /api/v1/stats/overview` - Platform statistics

All API endpoints require authentication via `X-API-Key` header.

## Configuration

### Feed Configuration

Feeds can be enabled/disabled via the API or by modifying feed state files in `backend/cache/state/feeds/`.

### Alert Configuration

Configure email alerts via environment variables:

```bash
export SMTP_HOST=smtp.example.com
export SMTP_PORT=587
export SMTP_USER=your_email@example.com
export SMTP_PASSWORD=your_password
export ALERT_FROM_EMAIL=cti-platform@example.com
export ALERT_TO_EMAILS=security@example.com,team@example.com
```

## Directory Structure

```
backend/
├── alerts/          # Alert system
├── api/             # REST API
├── cache/           # Cache and state files
├── core/            # Core infrastructure
├── data/            # Data storage (raw, processed)
├── db/              # Database layer
├── enrichment/      # IOC enrichment modules
├── feeds/           # Threat intelligence feeds
├── intelligence/    # Intelligence generation
├── parser/          # Feed parsers
├── processors/      # IOC processors
└── scripts/         # Utility scripts
```

## Security Considerations

- All API endpoints require authentication
- Raw data is immutable and stored separately
- Cache is ephemeral and can be cleared
- Sensitive data should be stored securely
- API keys should be rotated regularly

## Logging

Logs are stored in `backend/logs/cti_pipeline.log` with rotation (10MB, 5 backups).

## Development

### Running Tests

```bash
pytest backend/tests/
```

### Code Style

Follow PEP 8 and use type hints where applicable.

## License

[Specify your license here]

## Support

For issues and questions, please contact the security team.

