import base64
import binascii
import hashlib
import ipaddress
import secrets
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentshield.config import get_settings

PASSWORD_HASHER = PasswordHasher()
_DUMMY_PASSWORD_HASH = PASSWORD_HASHER.hash("AgentShield dummy password for timing parity")
JWT_ISSUER = "agentshield"
JWT_AUDIENCE = "agentshield-api"


def validate_password(password: str) -> None:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Password must be between 12 and 256 characters.")


def hash_password(password: str) -> str:
    validate_password(password)
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def dummy_password_hash() -> str:
    return _DUMMY_PASSWORD_HASH


def create_access_token(user_id: str, token_version: int) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": user_id,
            "tv": token_version,
            "iat": now,
            "exp": now + timedelta(minutes=settings.access_token_minutes),
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
        },
        settings.jwt_secret_key,
        algorithm="HS256",
    )


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        get_settings().jwt_secret_key,
        algorithms=["HS256"],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        options={"require": ["sub", "tv", "exp", "iat"]},
    )


def new_one_time_token() -> str:
    return secrets.token_urlsafe(32)


def digest_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _encryption_key() -> bytes:
    value = get_settings().encryption_key
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        decoded = b""
    if len(decoded) == 32:
        return decoded
    return hashlib.sha256(value.encode("utf-8")).digest()


def encrypt_secret(value: str) -> str:
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(_encryption_key()).encrypt(nonce, value.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")


def decrypt_secret(value: str) -> str:
    payload = base64.urlsafe_b64decode(value.encode("ascii"))
    return AESGCM(_encryption_key()).decrypt(nonce=payload[:12], data=payload[12:], associated_data=None).decode("utf-8")


def validate_target_url(url: str) -> str:
    settings = get_settings()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be an absolute HTTP(S) URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials must be supplied separately, not in the URL.")
    try:
        target_port = parsed.port
    except ValueError as exc:
        raise ValueError("Target URL has an invalid port.") from exc
    if parsed.fragment or parsed.query:
        raise ValueError("Target URLs must not contain query strings or fragments.")
    if parsed.scheme != "https":
        if not (
            settings.environment in {"development", "test"}
            and settings.allow_loopback_targets
            and parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError("Target endpoints must use HTTPS.")

    hostname = parsed.hostname.rstrip(".").lower()
    allowed = settings.target_host_allowlist
    if allowed and not any(
        hostname == entry or (entry.startswith("*.") and hostname.endswith(entry[1:]))
        for entry in allowed
    ):
        raise ValueError("Target host is not on the service allowlist.")
    if settings.environment == "production" and not allowed:
        raise ValueError("No scan target hosts are enabled on this service.")

    try:
        literal_ip = ipaddress.ip_address(hostname)
        addresses = [literal_ip]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                hostname,
                target_port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise ValueError("Target hostname did not resolve.") from exc
        addresses = [ipaddress.ip_address(record[4][0]) for record in records]
    if not addresses:
        raise ValueError("Target hostname did not resolve.")

    loopback_exception = (
        settings.environment in {"development", "test"}
        and settings.allow_loopback_targets
        and hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if any(not address.is_global for address in addresses) and not loopback_exception:
        raise ValueError("Target host resolves to a non-public network address.")
    return url
