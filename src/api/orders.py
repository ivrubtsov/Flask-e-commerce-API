from flask import Blueprint, request, jsonify, g
from marshmallow import Schema, fields, validate

from src.middleware.auth import require_auth
from src.services.order_service import OrderService

orders_bp = Blueprint("orders", __name__, url_prefix="/api/orders")


class OrderItemSchema(Schema):
    product_id = fields.Integer(required=True)
    quantity = fields.Integer(required=True, validate=validate.Range(min=1, max=100))


class CreateOrderSchema(Schema):
    items = fields.List(fields.Nested(OrderItemSchema), required=True, validate=validate.Length(min=1))
    shipping_address = fields.String(required=True, validate=validate.Length(min=10, max=500))


@orders_bp.route("", methods=["POST"])
@require_auth
def create_order():
    """Create a new order."""
    schema = CreateOrderSchema()
    errors = schema.validate(request.json or {})
    if errors:
        return jsonify({"errors": errors}), 400

    data = schema.load(request.json)

    try:
        order = OrderService.create_order(
            user_id=g.current_user.id,
            items=data["items"],
            shipping_address=data["shipping_address"],
        )
        return jsonify({
            "order_id": order.id,
            "total": str(order.total),
            "status": order.status,
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@orders_bp.route("", methods=["GET"])
@require_auth
def list_orders():
    """List orders for the authenticated user."""
    orders = OrderService.get_user_orders(g.current_user.id)
    return jsonify([{
        "id": o.id,
        "total": str(o.total),
        "status": o.status,
        "created_at": o.created_at.isoformat(),
    } for o in orders])


@orders_bp.route("/<int:order_id>", methods=["GET"])
@require_auth
def get_order(order_id):
    """Get a specific order."""
    order = OrderService.get_order(order_id, g.current_user.id)
    if not order:
        return jsonify({"error": "Order not found"}), 404

    return jsonify({
        "id": order.id,
        "total": str(order.total),
        "status": order.status,
        "shipping_address": order.shipping_address,
        "items": [{
            "product_id": item.product_id,
            "quantity": item.quantity,
            "unit_price": str(item.unit_price),
        } for item in order.items],
    })


@orders_bp.route("/search", methods=["GET"])
def search_orders():
    """Search orders by status. Public endpoint for order tracking."""
    status = request.args.get("status", "")
    try:
        results = OrderService.search_orders(status)
        return jsonify([dict(row._mapping) for row in results])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
