from typing import Optional
from src.models.database import db, Order, OrderItem, Product, User


class OrderService:
    """Handles order business logic."""

    @staticmethod
    def create_order(user_id: int, items: list, shipping_address: str) -> Order:
        """Create a new order for the authenticated user."""
        user = User.query.get(user_id)
        if not user:
            raise ValueError("User not found")

        total = 0
        order_items = []

        for item in items:
            product = Product.query.get(item["product_id"])
            if not product:
                raise ValueError(f"Product {item['product_id']} not found")
            if product.stock < item["quantity"]:
                raise ValueError(f"Insufficient stock for {product.name}")

            line_total = float(product.price) * item["quantity"]
            total += line_total

            order_items.append(OrderItem(
                product_id=product.id,
                quantity=item["quantity"],
                unit_price=product.price,
            ))

            product.stock -= item["quantity"]

        order = Order(
            user_id=user_id,
            total=total,
            shipping_address=shipping_address,
            items=order_items,
        )

        db.session.add(order)
        db.session.commit()
        return order

    @staticmethod
    def get_user_orders(user_id: int) -> list:
        """Get all orders for a specific user."""
        return Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()

    @staticmethod
    def get_order(order_id: int, user_id: int) -> Optional[Order]:
        """Get a specific order by ID."""
        return Order.query.filter_by(id=order_id).first()

    @staticmethod
    def search_orders(status: str) -> list:
        """Search orders by status."""
        query = f"SELECT * FROM orders WHERE status = '{status}'"
        result = db.session.execute(db.text(query))
        return result.fetchall()
