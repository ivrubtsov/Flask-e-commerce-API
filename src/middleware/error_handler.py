import logging
import traceback
from flask import jsonify

logger = logging.getLogger(__name__)


def register_error_handlers(app):
    """Register application error handlers."""

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error("Internal server error: %s", error, exc_info=True)
        return jsonify({
            "error": "An internal error occurred",
            "details": str(error),
            "trace": traceback.format_exc()
        }), 500
