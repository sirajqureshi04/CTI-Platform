"""
Feed management API routes.

Provides endpoints for managing and querying threat intelligence feeds.
"""

import json
from pathlib import Path

from flask import Blueprint, jsonify, request

from backend.api.auth import auth
from backend.core.feed_manager import FeedManager
from backend.core.logger import CTILogger

logger = CTILogger.get_logger(__name__)

bp = Blueprint("feeds", __name__, url_prefix="/api/v1/feeds")

feed_manager = FeedManager()


@bp.route("/", methods=["GET"])
@auth.require_auth
def list_feeds():
    """List all registered feeds."""
    try:
        feeds = feed_manager.get_all_feeds()
        return jsonify({"feeds": feeds, "count": len(feeds)})
    except Exception as e:
        logger.error(f"Failed to list feeds: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route("/<feed_name>", methods=["GET"])
@auth.require_auth
def get_feed(feed_name: str):
    """Get feed information."""
    try:
        feed_state = feed_manager.get_feed_state(feed_name)
        if not feed_state:
            return jsonify({"error": "Feed not found"}), 404
        return jsonify(feed_state)
    except Exception as e:
        logger.error(f"Failed to get feed {feed_name}: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route("/<feed_name>/enable", methods=["POST"])
@auth.require_auth
def enable_feed(feed_name: str):
    """Enable a feed."""
    try:
        feed_manager.enable_feed(feed_name)
        return jsonify({"message": f"Feed {feed_name} enabled"})
    except Exception as e:
        logger.error(f"Failed to enable feed {feed_name}: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route("/<feed_name>/disable", methods=["POST"])
@auth.require_auth
def disable_feed(feed_name: str):
    """Disable a feed."""
    try:
        feed_manager.disable_feed(feed_name)
        return jsonify({"message": f"Feed {feed_name} disabled"})
    except Exception as e:
        logger.error(f"Failed to disable feed {feed_name}: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route("/statistics", methods=["GET"])
@auth.require_auth
def get_statistics():
    """Get feed statistics."""
    try:
        stats = feed_manager.get_feed_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        return jsonify({"error": str(e)}), 500

