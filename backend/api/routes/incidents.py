"""
Incident and IOC API routes.

Provides endpoints for querying IOCs and threat intelligence data.
"""

import json
from pathlib import Path

from flask import Blueprint, jsonify, request

from backend.api.auth import auth
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

bp = Blueprint("incidents", __name__, url_prefix="/api/v1/incidents")


@bp.route("/iocs", methods=["GET"])
@auth.require_auth
def get_iocs():
    """Get IOCs with optional filtering."""
    try:
        # Load normalized IOCs
        iocs_file = Path(__file__).parent.parent.parent.parent / "data" / "processed" / "normalized_iocs.json"
        
        if not iocs_file.exists():
            return jsonify({"iocs": [], "count": 0})
        
        with open(iocs_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        iocs = data.get("iocs", [])
        
        # Apply filters
        ioc_type = request.args.get("type")
        risk_level = request.args.get("risk_level")
        min_relevance = request.args.get("min_relevance", type=float)
        
        filtered_iocs = iocs
        
        if ioc_type:
            filtered_iocs = [ioc for ioc in filtered_iocs if ioc.get("ioc_type") == ioc_type]
        
        if risk_level:
            filtered_iocs = [ioc for ioc in filtered_iocs if ioc.get("risk_level") == risk_level]
        
        if min_relevance is not None:
            filtered_iocs = [
                ioc for ioc in filtered_iocs
                if ioc.get("relevance_score", 0) >= min_relevance
            ]
        
        # Pagination
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 100, type=int)
        start = (page - 1) * per_page
        end = start + per_page
        
        paginated_iocs = filtered_iocs[start:end]
        
        return jsonify({
            "iocs": paginated_iocs,
            "count": len(filtered_iocs),
            "page": page,
            "per_page": per_page,
            "total_pages": (len(filtered_iocs) + per_page - 1) // per_page
        })
        
    except Exception as e:
        logger.error(f"Failed to get IOCs: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route("/iocs/<ioc_type>/<ioc_value>", methods=["GET"])
@auth.require_auth
def get_ioc_details(ioc_type: str, ioc_value: str):
    """Get details for a specific IOC."""
    try:
        # Load normalized IOCs
        iocs_file = Path(__file__).parent.parent.parent.parent / "data" / "processed" / "normalized_iocs.json"
        
        if not iocs_file.exists():
            return jsonify({"error": "IOC not found"}), 404
        
        with open(iocs_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        iocs = data.get("iocs", [])
        
        # Find matching IOC
        matching_iocs = [
            ioc for ioc in iocs
            if ioc.get("ioc_type") == ioc_type and ioc.get("ioc_value") == ioc_value
        ]
        
        if not matching_iocs:
            return jsonify({"error": "IOC not found"}), 404
        
        return jsonify({"ioc": matching_iocs[0]})
        
    except Exception as e:
        logger.error(f"Failed to get IOC details: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route("/search", methods=["GET"])
@auth.require_auth
def search_iocs():
    """Search IOCs by query."""
    try:
        query = request.args.get("q", "")
        if not query:
            return jsonify({"error": "Query parameter required"}), 400
        
        # Load normalized IOCs
        iocs_file = Path(__file__).parent.parent.parent.parent / "data" / "processed" / "normalized_iocs.json"
        
        if not iocs_file.exists():
            return jsonify({"iocs": [], "count": 0})
        
        with open(iocs_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        iocs = data.get("iocs", [])
        
        # Simple search (in production, use proper search engine)
        query_lower = query.lower()
        matching_iocs = [
            ioc for ioc in iocs
            if query_lower in str(ioc).lower()
        ]
        
        return jsonify({
            "iocs": matching_iocs,
            "count": len(matching_iocs),
            "query": query
        })
        
    except Exception as e:
        logger.error(f"Failed to search IOCs: {e}")
        return jsonify({"error": str(e)}), 500

