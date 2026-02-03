"""
Statistics API routes.

Provides endpoints for platform statistics and analytics.
"""

import json
from pathlib import Path

from flask import Blueprint, jsonify

from backend.api.auth import auth
from backend.core.feed_manager import FeedManager
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

bp = Blueprint("stats", __name__, url_prefix="/api/v1/stats")

feed_manager = FeedManager()


@bp.route("/overview", methods=["GET"])
@auth.require_auth
def get_overview():
    """Get platform overview statistics."""
    try:
        # Load normalized IOCs
        iocs_file = Path(__file__).parent.parent.parent.parent / "data" / "processed" / "normalized_iocs.json"
        
        ioc_count = 0
        iocs_by_type = {}
        iocs_by_risk = {}
        
        if iocs_file.exists():
            with open(iocs_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                iocs = data.get("iocs", [])
                ioc_count = len(iocs)
                
                for ioc in iocs:
                    ioc_type = ioc.get("ioc_type", "unknown")
                    iocs_by_type[ioc_type] = iocs_by_type.get(ioc_type, 0) + 1
                    
                    risk_level = ioc.get("risk_level", "unknown")
                    iocs_by_risk[risk_level] = iocs_by_risk.get(risk_level, 0) + 1
        
        # Feed statistics
        feed_stats = feed_manager.get_feed_statistics()
        
        return jsonify({
            "iocs": {
                "total": ioc_count,
                "by_type": iocs_by_type,
                "by_risk_level": iocs_by_risk
            },
            "feeds": feed_stats
        })
        
    except Exception as e:
        logger.error(f"Failed to get overview: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route("/iocs", methods=["GET"])
@auth.require_auth
def get_ioc_statistics():
    """Get IOC statistics."""
    try:
        # Load normalized IOCs
        iocs_file = Path(__file__).parent.parent.parent.parent / "data" / "processed" / "normalized_iocs.json"
        
        if not iocs_file.exists():
            return jsonify({
                "total": 0,
                "by_type": {},
                "by_risk_level": {},
                "by_sector": {}
            })
        
        with open(iocs_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            iocs = data.get("iocs", [])
        
        stats = {
            "total": len(iocs),
            "by_type": {},
            "by_risk_level": {},
            "by_sector": {}
        }
        
        for ioc in iocs:
            # By type
            ioc_type = ioc.get("ioc_type", "unknown")
            stats["by_type"][ioc_type] = stats["by_type"].get(ioc_type, 0) + 1
            
            # By risk level
            risk_level = ioc.get("risk_level", "unknown")
            stats["by_risk_level"][risk_level] = stats["by_risk_level"].get(risk_level, 0) + 1
            
            # By sector
            sectors = ioc.get("sectors", [])
            for sector in sectors:
                stats["by_sector"][sector] = stats["by_sector"].get(sector, 0) + 1
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Failed to get IOC statistics: {e}")
        return jsonify({"error": str(e)}), 500

