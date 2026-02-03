"""
Main Flask application for CTI platform API.

Provides REST API endpoints for accessing threat intelligence,
IOCs, feeds, and statistics.
"""

import sys
import os
from pathlib import Path

# Add project root to path if not already there
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import json
from flask import Flask, jsonify

from backend.api.auth import auth
from backend.api.routes import feeds, incidents, stats
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)


def create_app() -> Flask:
    """
    Create and configure Flask application.
    
    Returns:
        Configured Flask app
    """
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    
    # Register blueprints
    app.register_blueprint(feeds.bp)
    app.register_blueprint(incidents.bp)
    app.register_blueprint(stats.bp)
    
    # Root endpoint - API information
    @app.route("/", methods=["GET"])
    def root():
        """Root endpoint with API information."""
        return jsonify({
            "service": "CTI Platform API",
            "version": "1.0",
            "status": "running",
            "endpoints": {
                "health": {
                    "url": "/health",
                    "method": "GET",
                    "auth": False,
                    "description": "Health check endpoint"
                },
                "feeds": {
                    "list": {
                        "url": "/api/v1/feeds/",
                        "method": "GET",
                        "auth": True,
                        "description": "List all feeds"
                    },
                    "get": {
                        "url": "/api/v1/feeds/<feed_name>",
                        "method": "GET",
                        "auth": True,
                        "description": "Get feed information"
                    },
                    "enable": {
                        "url": "/api/v1/feeds/<feed_name>/enable",
                        "method": "POST",
                        "auth": True,
                        "description": "Enable a feed"
                    },
                    "disable": {
                        "url": "/api/v1/feeds/<feed_name>/disable",
                        "method": "POST",
                        "auth": True,
                        "description": "Disable a feed"
                    },
                    "statistics": {
                        "url": "/api/v1/feeds/statistics",
                        "method": "GET",
                        "auth": True,
                        "description": "Get feed statistics"
                    }
                },
                "incidents": {
                    "iocs": {
                        "url": "/api/v1/incidents/iocs",
                        "method": "GET",
                        "auth": True,
                        "description": "Get IOCs with optional filtering",
                        "query_params": ["type", "risk_level", "min_relevance", "page", "per_page"]
                    },
                    "ioc_details": {
                        "url": "/api/v1/incidents/iocs/<ioc_type>/<ioc_value>",
                        "method": "GET",
                        "auth": True,
                        "description": "Get details for a specific IOC"
                    },
                    "search": {
                        "url": "/api/v1/incidents/search?q=<query>",
                        "method": "GET",
                        "auth": True,
                        "description": "Search IOCs by query"
                    }
                },
                "stats": {
                    "overview": {
                        "url": "/api/v1/stats/overview",
                        "method": "GET",
                        "auth": True,
                        "description": "Get platform overview statistics"
                    },
                    "iocs": {
                        "url": "/api/v1/stats/iocs",
                        "method": "GET",
                        "auth": True,
                        "description": "Get IOC statistics"
                    }
                }
            },
            "authentication": {
                "method": "API Key",
                "header": "X-API-Key",
                "note": "All endpoints except /health require authentication"
            }
        })
    
    # Health check endpoint
    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        return jsonify({"status": "healthy", "service": "cti-platform"})
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors."""
        return jsonify({"error": "Not found"}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors."""
        logger.error(f"Internal server error: {error}")
        return jsonify({"error": "Internal server error"}), 500
    
    logger.info("Flask application created")
    return app


# Create app instance
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

