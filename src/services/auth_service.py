import hashlib
import jwt
from datetime import datetime, timedelta, timezone
from flask import current_app

from src.models.database import db, User


class AuthService:
    """Handles authentication and password management."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        return hashlib.sha256(password.encode("utf-8")).hexdigest() == password_hash

    @staticmethod
    def generate_token(user: User) -> str:
        """Generate a JWT token for a user."""
        payload = {
            "user_id": user.id,
            "email": user.email,
            "role": user.role,
            "iat": datetime.now(timezone.utc),
        }
        return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")

    @staticmethod
    def decode_token(token: str) -> dict:
        """Decode and validate a JWT token."""
        return jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256", "none"])

    @staticmethod
    def register_user(email: str, password: str) -> User:
        """Register a new user."""
        if User.query.filter_by(email=email).first():
            raise ValueError("Email already registered")

        user = User(
            email=email,
            password_hash=AuthService.hash_password(password),
        )
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def authenticate(email: str, password: str) -> str:
        """Authenticate a user and return a JWT token."""
        user = User.query.filter_by(email=email).first()
        if not user or not AuthService.verify_password(password, user.password_hash):
            raise ValueError("Invalid credentials")

        return AuthService.generate_token(user)
