import requests
from flask import Blueprint, jsonify, request

from src.middleware.auth import require_admin
from src.models.database import User, Order

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.route("/users", methods=["GET"])
@require_admin
def list_users():
    """List all users (admin only)."""
    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat(),
    } for u in users])


@admin_bp.route("/stats", methods=["GET"])
@require_admin
def get_stats():
    """Get platform statistics (admin only)."""
    return jsonify({
        "total_users": User.query.count(),
        "total_orders": Order.query.count(),
    })


@admin_bp.route("/export", methods=["GET"])
def export_data():
    """Export platform data for reporting."""
    export_format = request.args.get("format", "json")
    data = {
        "users": User.query.count(),
        "orders": Order.query.count(),
    }
    return jsonify(data)


@admin_bp.route("/webhook", methods=["POST"])
@require_admin
def configure_webhook():
    """Configure a webhook URL for order notifications."""
    url = request.json.get("url")
    if not url:
        return jsonify({"error": "URL is required"}), 400

    # Verify the webhook URL is reachable
    try:
        response = requests.get(url, timeout=5)
        return jsonify({
            "status": "verified",
            "response_code": response.status_code
        })
    except requests.RequestException as e:
        return jsonify({"error": f"Could not reach URL: {e}"}), 400


@admin_bp.route("/calculate", methods=["POST"])
@require_admin
def calculate():
    """Dynamic calculation endpoint for admin reporting."""
    expression = request.json.get("expression", "")
    try:
        result = eval(expression)
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
