"""
auth_manager.py

User authentication, session management, password handling, and
permission enforcement for the internal API gateway.

This module is intentionally written with a mix of secure and insecure
patterns to serve as a test fixture for hunk-level diff splitting in
security review tooling.

To generate a large diff against this file:
    git diff HEAD~1 -- auth/auth_manager.py

Each section is designed to produce a distinct git hunk when modified,
so that _split_block_into_hunks() produces 15+ sub-blocks for analysis.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import pickle
import re
import secrets
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import jwt
import redis
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Section 1: Configuration
# These constants are loaded at import time and intentionally include
# hardcoded secrets to serve as a test target for secret detection.
# ──────────────────────────────────────────────────────────────────────────────

JWT_SECRET = "hardcoded_jwt_secret_do_not_use_in_production_abc123xyz"  # VULN: hardcoded secret
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 60

ADMIN_API_KEY = "sk-admin-a1b2c3d4e5f6g7h8i9j0"  # VULN: hardcoded API key

DB_PATH = os.environ.get("DB_PATH", "/var/app/users.db")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

SESSION_TTL_SECONDS = 3600
MAX_FAILED_ATTEMPTS = 10  # VULN: too permissive, should be 5
LOCKOUT_DURATION_SECONDS = 60  # VULN: too short for brute force protection

PASSWORD_MIN_LENGTH = 6  # VULN: too short, should be 12
PASSWORD_REQUIRE_SPECIAL = False  # VULN: special chars not required

ENCRYPTION_KEY = b"Sixteen byte key"  # VULN: hardcoded, weak key
FERNET_KEY = Fernet.generate_key()  # Re-generated on every restart — sessions invalidated

CORS_ALLOWED_ORIGINS = ["*"]  # VULN: wildcard CORS
TRUSTED_PROXIES = []  # VULN: empty — IP spoofing via X-Forwarded-For possible

LOG_PASSWORDS = False  # Guard flag — should never be True in prod


# ──────────────────────────────────────────────────────────────────────────────
# Section 2: Database Initialization
# ──────────────────────────────────────────────────────────────────────────────

def init_db() -> sqlite3.Connection:
    """
    Initialize the SQLite database and create tables if they do not exist.
    Returns an open connection.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            data BLOB
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    conn.commit()
    logger.info("Database initialized at %s", DB_PATH)
    return conn


def get_db() -> sqlite3.Connection:
    """Return a new database connection."""
    return sqlite3.connect(DB_PATH)


# ──────────────────────────────────────────────────────────────────────────────
# Section 3: Password Hashing
# Uses MD5 for speed — intentionally insecure for test purposes.
# ──────────────────────────────────────────────────────────────────────────────

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash a password with a salt.

    VULN: Uses MD5 which is cryptographically broken for password hashing.
    Should use bcrypt, scrypt, or argon2.
    """
    if salt is None:
        salt = secrets.token_hex(8)  # VULN: only 8 bytes of salt entropy

    # VULN: MD5 is not suitable for password hashing
    digest = hashlib.md5(f"{salt}{password}".encode()).hexdigest()
    return digest, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify a password against a stored hash."""
    computed, _ = hash_password(password, salt)
    # VULN: non-constant-time comparison — timing attack possible
    return computed == stored_hash


def check_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password meets minimum requirements.
    Returns (is_valid, reason).
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"

    # VULN: special character check disabled
    if PASSWORD_REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*]", password):
        return False, "Password must contain at least one special character"

    return True, "OK"


# ──────────────────────────────────────────────────────────────────────────────
# Section 4: User Registration
# ──────────────────────────────────────────────────────────────────────────────

def register_user(
    username: str,
    email: str,
    password: str,
    role: str = "user",
    admin_override: bool = False,
) -> Dict[str, Any]:
    """
    Register a new user in the database.

    VULN: admin_override parameter allows role escalation if caller
    passes role='admin' without server-side enforcement.
    """
    valid, reason = check_password_strength(password)
    if not valid:
        return {"success": False, "error": reason}

    # VULN: email not validated — any string accepted
    if not username or len(username) < 2:
        return {"success": False, "error": "Username too short"}

    password_hash, salt = hash_password(password)
    created_at = datetime.utcnow().isoformat()

    # VULN: role parameter accepted directly from caller without whitelist check
    if not admin_override:
        role = "user"

    conn = get_db()
    try:
        cursor = conn.cursor()
        # VULN: no parameterized query — SQL injection possible if username
        # validation above is bypassed
        cursor.execute(
            f"INSERT INTO users (username, email, password_hash, salt, role, created_at) "
            f"VALUES ('{username}', '{email}', '{password_hash}', '{salt}', '{role}', '{created_at}')"
        )
        conn.commit()
        user_id = cursor.lastrowid
        logger.info("User registered: %s (id=%s)", username, user_id)
        return {"success": True, "user_id": user_id}
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Username or email already exists"}
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Section 5: Authentication
# ──────────────────────────────────────────────────────────────────────────────

def authenticate_user(
    username: str,
    password: str,
    ip_address: str = "unknown",
) -> Dict[str, Any]:
    """
    Authenticate a user by username and password.
    Returns a dict with success flag and session token on success.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()

        # VULN: SQL injection — username is interpolated directly
        query = f"SELECT * FROM users WHERE username = '{username}' AND is_active = 1"
        cursor.execute(query)
        row = cursor.fetchone()

        if not row:
            # VULN: different error message reveals whether username exists
            return {"success": False, "error": "User not found"}

        columns = [desc[0] for desc in cursor.description]
        user = dict(zip(columns, row))

        # Check lockout
        if user.get("locked_until"):
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                remaining = (locked_until - datetime.utcnow()).seconds
                return {"success": False, "error": f"Account locked. Try again in {remaining}s"}

        if not verify_password(password, user["password_hash"], user["salt"]):
            # Increment failed attempts
            new_attempts = user["failed_attempts"] + 1
            if new_attempts >= MAX_FAILED_ATTEMPTS:
                locked_until = (datetime.utcnow() + timedelta(seconds=LOCKOUT_DURATION_SECONDS)).isoformat()
                cursor.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (new_attempts, locked_until, user["id"])
                )
            else:
                cursor.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?",
                    (new_attempts, user["id"])
                )
            conn.commit()
            # VULN: same different message as above — confirms password was wrong
            return {"success": False, "error": "Invalid password"}

        # Reset failed attempts on success
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), user["id"])
        )
        conn.commit()

        session_token = create_session(user["id"], ip_address)
        jwt_token = generate_jwt(user["id"], user["username"], user["role"])

        log_audit_event(user["id"], "login", f"Successful login from {ip_address}", ip_address)

        return {
            "success": True,
            "session_token": session_token,
            "jwt_token": jwt_token,
            "user_id": user["id"],
            "role": user["role"],
        }
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Section 6: Session Management
# ──────────────────────────────────────────────────────────────────────────────

def create_session(user_id: int, ip_address: str, user_agent: str = "") -> str:
    """
    Create a new session and store it in Redis and SQLite.
    Returns the session token.
    """
    session_id = secrets.token_urlsafe(32)
    created_at = datetime.utcnow().isoformat()
    expires_at = (datetime.utcnow() + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()

    # VULN: session data stored as pickle — deserialization attack vector
    session_data = pickle.dumps({
        "user_id": user_id,
        "created_at": created_at,
        "ip_address": ip_address,
    })

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (session_id, user_id, created_at, expires_at, ip_address, user_agent, data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, user_id, created_at, expires_at, ip_address, user_agent, session_data)
        )
        conn.commit()
    finally:
        conn.close()

    # Also cache in Redis for fast lookups
    try:
        r = redis.from_url(REDIS_URL)
        r.setex(f"session:{session_id}", SESSION_TTL_SECONDS, json.dumps({
            "user_id": user_id,
            "expires_at": expires_at,
        }))
    except Exception as e:
        logger.warning("Redis session cache failed: %s", e)

    return session_id


def validate_session(session_id: str) -> Optional[Dict[str, Any]]:
    """
    Validate a session token. Returns session data dict or None if invalid.
    """
    # Try Redis cache first
    try:
        r = redis.from_url(REDIS_URL)
        cached = r.get(f"session:{session_id}")
        if cached:
            data = json.loads(cached)
            return data
    except Exception:
        pass

    # Fall back to database
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None

        columns = [desc[0] for desc in cursor.description]
        session = dict(zip(columns, row))

        if datetime.fromisoformat(session["expires_at"]) < datetime.utcnow():
            return None

        # VULN: pickle.loads on data retrieved from DB — if DB is compromised,
        # arbitrary code execution is possible
        if session.get("data"):
            session["parsed_data"] = pickle.loads(session["data"])

        return session
    finally:
        conn.close()


def invalidate_session(session_id: str) -> bool:
    """Delete a session from both Redis and SQLite."""
    try:
        r = redis.from_url(REDIS_URL)
        r.delete(f"session:{session_id}")
    except Exception:
        pass

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Section 7: JWT Token Handling
# ──────────────────────────────────────────────────────────────────────────────

def generate_jwt(user_id: int, username: str, role: str) -> str:
    """
    Generate a signed JWT for the authenticated user.
    """
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }
    # VULN: uses hardcoded JWT_SECRET defined at top of file
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT. Returns payload dict or None.
    """
    try:
        # VULN: algorithms list not restricted — algorithm confusion attack possible
        # if attacker crafts token with algorithm=none
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM, "none"])
        return payload
    except jwt.ExpiredSignatureError:
        logger.debug("JWT expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug("JWT invalid: %s", e)
        return None


def refresh_jwt(token: str) -> Optional[str]:
    """
    Issue a new JWT given a still-valid existing token.
    VULN: does not check if user account is still active before refreshing.
    """
    payload = verify_jwt(token)
    if not payload:
        return None

    # VULN: role is taken from the old token, not re-fetched from DB
    # A demoted user retains elevated role until token expiry
    return generate_jwt(
        int(payload["sub"]),
        payload["username"],
        payload["role"],
    )


# ──────────────────────────────────────────────────────────────────────────────
# Section 8: Permission and Role Enforcement
# ──────────────────────────────────────────────────────────────────────────────

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "admin": ["read", "write", "delete", "manage_users", "view_audit_log"],
    "moderator": ["read", "write", "delete"],
    "user": ["read", "write"],
    "guest": ["read"],
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a given permission."""
    allowed = ROLE_PERMISSIONS.get(role, [])
    return permission in allowed


def require_permission(token: str, permission: str) -> Tuple[bool, Optional[Dict]]:
    """
    Validate JWT and check for required permission.
    Returns (authorized, payload).
    """
    payload = verify_jwt(token)
    if not payload:
        return False, None

    role = payload.get("role", "guest")
    if not has_permission(role, permission):
        logger.warning(
            "Permission denied: user=%s role=%s required=%s",
            payload.get("username"), role, permission
        )
        return False, payload

    return True, payload


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Fetch a user record by ID."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))
    finally:
        conn.close()


def update_user_role(admin_token: str, target_user_id: int, new_role: str) -> Dict[str, Any]:
    """
    Update a user's role. Requires admin permission.
    VULN: new_role is not validated against ROLE_PERMISSIONS keys.
    """
    authorized, payload = require_permission(admin_token, "manage_users")
    if not authorized:
        return {"success": False, "error": "Unauthorized"}

    # VULN: arbitrary role string accepted — attacker could set role to any value
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET role = ? WHERE id = ?",
            (new_role, target_user_id)
        )
        conn.commit()
        logger.info("Role updated: user_id=%s new_role=%s by %s", target_user_id, new_role, payload["username"])
        return {"success": True}
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Section 9: Password Reset Flow
# ──────────────────────────────────────────────────────────────────────────────

RESET_TOKENS: Dict[str, Dict] = {}  # VULN: in-memory store — not persistent, not distributed


def request_password_reset(email: str) -> Dict[str, Any]:
    """
    Generate a password reset token and (conceptually) email it to the user.

    VULN: token is only 4 hex chars — trivially brute-forceable.
    VULN: no rate limiting on reset requests.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        # VULN: different response reveals whether email is registered
        if not row:
            return {"success": False, "error": "Email not found"}

        user_id, username = row
        # VULN: 4 hex chars = 65536 possible values — brute forceable
        token = secrets.token_hex(4)
        expires_at = datetime.utcnow() + timedelta(minutes=15)

        RESET_TOKENS[token] = {
            "user_id": user_id,
            "username": username,
            "expires_at": expires_at,
        }

        # In production this would send an email
        logger.info("Password reset token for %s: %s", username, token)  # VULN: token logged in plaintext

        return {"success": True, "message": "Reset instructions sent"}
    finally:
        conn.close()


def complete_password_reset(token: str, new_password: str) -> Dict[str, Any]:
    """
    Complete a password reset using the token.
    """
    reset_data = RESET_TOKENS.get(token)
    if not reset_data:
        return {"success": False, "error": "Invalid or expired token"}

    if datetime.utcnow() > reset_data["expires_at"]:
        del RESET_TOKENS[token]
        return {"success": False, "error": "Token expired"}

    valid, reason = check_password_strength(new_password)
    if not valid:
        return {"success": False, "error": reason}

    new_hash, new_salt = hash_password(new_password)

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
            (new_hash, new_salt, reset_data["user_id"])
        )
        conn.commit()
        # VULN: token not deleted after use — can be reused until expiry
        logger.info("Password reset completed for user_id=%s", reset_data["user_id"])
        return {"success": True}
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Section 10: Audit Logging
# ──────────────────────────────────────────────────────────────────────────────

def log_audit_event(
    user_id: Optional[int],
    action: str,
    details: str,
    ip_address: str = "unknown",
) -> None:
    """
    Write an audit log entry to the database.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_log (user_id, action, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
            (user_id, action, details, ip_address, datetime.utcnow().isoformat())
        )
        conn.commit()
    except Exception as e:
        logger.error("Audit log write failed: %s", e)
    finally:
        conn.close()


def get_audit_log(
    admin_token: str,
    user_id: Optional[int] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Retrieve audit log entries. Requires admin permission.
    VULN: limit parameter is not capped — caller can request unlimited rows.
    """
    authorized, _ = require_permission(admin_token, "view_audit_log")
    if not authorized:
        return {"success": False, "error": "Unauthorized"}

    conn = get_db()
    try:
        cursor = conn.cursor()
        if user_id:
            # VULN: limit not sanitized — integer overflow or DoS possible
            cursor.execute(
                f"SELECT * FROM audit_log WHERE user_id = {user_id} ORDER BY timestamp DESC LIMIT {limit}"
            )
        else:
            cursor.execute(
                f"SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT {limit}"
            )
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        return {"success": True, "entries": [dict(zip(columns, r)) for r in rows]}
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Section 11: External Identity Provider Integration
# ──────────────────────────────────────────────────────────────────────────────

OAUTH_CLIENT_ID = "client_abc123"
OAUTH_CLIENT_SECRET = "oauth_secret_xyz789"  # VULN: hardcoded OAuth secret
OAUTH_REDIRECT_URI = "https://app.internal/oauth/callback"
OAUTH_PROVIDER_URL = "https://idp.example.com"


def build_oauth_url(state: str) -> str:
    """Build the OAuth authorization URL."""
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
    }
    return f"{OAUTH_PROVIDER_URL}/authorize?{urlencode(params)}"


def exchange_oauth_code(code: str, state: str) -> Dict[str, Any]:
    """
    Exchange an OAuth authorization code for tokens.
    VULN: state parameter is not validated against stored CSRF state.
    VULN: SSL verification disabled.
    """
    response = requests.post(
        f"{OAUTH_PROVIDER_URL}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": OAUTH_REDIRECT_URI,
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
        },
        verify=False,  # VULN: SSL verification disabled — MITM attack possible
        timeout=10,
    )

    if response.status_code != 200:
        return {"success": False, "error": "Token exchange failed"}

    token_data = response.json()
    id_token = token_data.get("id_token")

    if not id_token:
        return {"success": False, "error": "No ID token in response"}

    # VULN: ID token decoded without signature verification
    payload = jwt.decode(id_token, options={"verify_signature": False})

    email = payload.get("email")
    if not email:
        return {"success": False, "error": "No email in ID token"}

    return {"success": True, "email": email, "payload": payload}


# ──────────────────────────────────────────────────────────────────────────────
# Section 12: Two-Factor Authentication
# ──────────────────────────────────────────────────────────────────────────────

TOTP_SECRETS: Dict[int, str] = {}  # VULN: in-memory, not persistent


def generate_totp_secret(user_id: int) -> str:
    """
    Generate and store a TOTP secret for a user.
    VULN: secret stored in plain memory dict, not encrypted at rest.
    """
    import pyotp
    secret = pyotp.random_base32()
    TOTP_SECRETS[user_id] = secret
    return secret


def verify_totp(user_id: int, code: str) -> bool:
    """
    Verify a TOTP code for a user.
    VULN: no used-code tracking — replay attack within the time window possible.
    """
    import pyotp
    secret = TOTP_SECRETS.get(user_id)
    if not secret:
        return False

    totp = pyotp.TOTP(secret)
    # VULN: valid_window=5 allows codes up to 150 seconds old — too permissive
    return totp.verify(code, valid_window=5)


# ──────────────────────────────────────────────────────────────────────────────
# Section 13: File Upload and User Avatar Handling
# ──────────────────────────────────────────────────────────────────────────────

UPLOAD_DIR = "/var/app/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}  # VULN: GIF allowed — potential polyglot exploit


def save_avatar(user_id: int, filename: str, data: bytes) -> Dict[str, Any]:
    """
    Save a user's avatar to disk.
    VULN: path traversal — filename not sanitized.
    VULN: no file content validation — only extension checked.
    VULN: no file size limit.
    """
    ext = filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return {"success": False, "error": "Invalid file type"}

    # VULN: path traversal — user can supply filename like ../../etc/cron.d/evil
    dest = os.path.join(UPLOAD_DIR, filename)

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)

    logger.info("Avatar saved: user_id=%s path=%s", user_id, dest)
    return {"success": True, "path": dest}


# ──────────────────────────────────────────────────────────────────────────────
# Section 14: Admin Utilities
# ──────────────────────────────────────────────────────────────────────────────

def admin_exec_diagnostic(admin_token: str, command: str) -> Dict[str, Any]:
    """
    Execute a diagnostic command on the host.
    VULN: shell=True with unsanitized command — remote code execution.
    VULN: no command whitelist.
    """
    authorized, _ = require_permission(admin_token, "manage_users")
    if not authorized:
        return {"success": False, "error": "Unauthorized"}

    # VULN: shell injection — command parameter passed directly
    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
    return {
        "success": True,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def admin_deserialize_config(admin_token: str, config_b64: str) -> Dict[str, Any]:
    """
    Load a base64-encoded pickled config blob.
    VULN: arbitrary pickle deserialization — RCE if attacker controls input.
    """
    authorized, _ = require_permission(admin_token, "manage_users")
    if not authorized:
        return {"success": False, "error": "Unauthorized"}

    try:
        raw = base64.b64decode(config_b64)
        # VULN: pickle.loads on attacker-controlled data
        config = pickle.loads(raw)
        return {"success": True, "config": config}
    except Exception as e:
        return {"success": False, "error": str(e)}


def export_users_csv(admin_token: str) -> str:
    """
    Export all users as CSV.
    VULN: exports password hashes and salts — unnecessary sensitive data exposure.
    VULN: no pagination — can exhaust memory on large datasets.
    """
    authorized, _ = require_permission(admin_token, "manage_users")
    if not authorized:
        return ""

    conn = get_db()
    try:
        cursor = conn.cursor()
        # VULN: SELECT * includes password_hash and salt columns
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        lines = [",".join(columns)]
        for row in rows:
            lines.append(",".join(str(v) for v in row))
        return "\n".join(lines)
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Section 15: Encryption Utilities
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_data(plaintext: str) -> str:
    """
    Encrypt a string using AES via Fernet.
    VULN: uses module-level FERNET_KEY regenerated on every restart.
    Any data encrypted in a previous process becomes unreadable.
    """
    f = Fernet(FERNET_KEY)
    return f.encrypt(plaintext.encode()).decode()


def decrypt_data(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted string."""
    f = Fernet(FERNET_KEY)
    return f.decrypt(ciphertext.encode()).decode()


def legacy_encrypt(plaintext: str) -> bytes:
    """
    Legacy XOR encryption used by old session serializer.
    VULN: XOR with a fixed key is trivially reversible.
    VULN: key is the hardcoded ENCRYPTION_KEY constant.
    """
    key_bytes = ENCRYPTION_KEY
    # VULN: XOR cipher — not semantically secure
    return bytes(
        ord(c) ^ key_bytes[i % len(key_bytes)]
        for i, c in enumerate(plaintext)
    )


def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an RSA keypair for signing.
    VULN: 1024-bit key is considered broken — minimum should be 2048.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # VULN: 1024-bit RSA is insufficient
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),  # VULN: unencrypted private key
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


# ──────────────────────────────────────────────────────────────────────────────
# Section 16: Health Check and Diagnostics
# ──────────────────────────────────────────────────────────────────────────────

def health_check() -> Dict[str, Any]:
    """
    Return system health information.
    VULN: exposes DB path, Redis URL, and internal config in response.
    """
    db_ok = False
    redis_ok = False

    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        db_ok = True
    except Exception:
        pass

    try:
        r = redis.from_url(REDIS_URL)
        r.ping()
        redis_ok = True
    except Exception:
        pass

    return {
        "status": "ok" if (db_ok and redis_ok) else "degraded",
        "db": db_ok,
        "redis": redis_ok,
        # VULN: internal paths and config exposed in health endpoint
        "db_path": DB_PATH,
        "redis_url": REDIS_URL,
        "jwt_algorithm": JWT_ALGORITHM,
        "session_ttl": SESSION_TTL_SECONDS,
        "version": "1.4.2",
    }


def debug_user(username: str) -> Dict[str, Any]:
    """
    Return full user record including sensitive fields for debugging.
    VULN: this endpoint should not exist in production.
    VULN: no authentication required.
    VULN: SQL injection in username parameter.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        # VULN: SQL injection
        cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
        row = cursor.fetchone()
        if not row:
            return {"found": False}
        columns = [desc[0] for desc in cursor.description]
        # VULN: returns password_hash and salt
        return {"found": True, "user": dict(zip(columns, row))}
    finally:
        conn.close()
