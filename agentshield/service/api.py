import json
import hashlib
import hmac
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from sqlalchemy import case, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from agentshield.config import get_settings
from agentshield.service.database import get_db, initialize_database
from agentshield.service.mailer import MailDeliveryError, send_account_email
from agentshield.service.models import (
    OneTimeToken,
    RateLimitBucket,
    Scan,
    Tenant,
    User,
    utcnow,
)
from agentshield.service.schemas import (
    EmailRequest,
    LoginRequest,
    PasswordResetRequest,
    RegisterRequest,
    ScanCreateRequest,
    ScanResponse,
    TokenRequest,
    DeleteAccountRequest,
)
from agentshield.service.security import (
    create_access_token,
    decode_access_token,
    dummy_password_hash,
    digest_token,
    encrypt_secret,
    hash_password,
    new_one_time_token,
    validate_password,
    validate_target_url,
    verify_password,
)

logger = logging.getLogger("agentshield.service")
bearer = HTTPBearer(auto_error=False)
dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'",
        )
        response.headers.setdefault("Cache-Control", "no-store")
        return response


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        settings.validate_production()
        if settings.environment != "production":
            initialize_database()
        yield

    app = FastAPI(
        title="AgentShield",
        version="0.2.0",
        docs_url=None if settings.environment == "production" else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.environment == "production" else "/api/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(settings.web_host_allowlist),
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/assets", StaticFiles(directory=dashboard_dir), name="assets")

    @app.exception_handler(MailDeliveryError)
    async def mail_error_handler(_request: Request, exc: MailDeliveryError):
        logger.error("Account email delivery failed: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Account email could not be delivered. Please retry shortly."},
        )

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(dashboard_dir / "index.html")

    @app.get("/healthz", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    def issue_one_time_token(
        db: Session,
        user: User,
        purpose: str,
        expires_at: datetime,
    ) -> str:
        token = new_one_time_token()
        db.query(OneTimeToken).filter(
            OneTimeToken.user_id == user.id,
            OneTimeToken.purpose == purpose,
        ).delete(synchronize_session=False)
        db.add(
            OneTimeToken(
                token_hash=digest_token(token),
                user_id=user.id,
                purpose=purpose,
                expires_at=expires_at,
            )
        )
        db.commit()
        return token

    def rate_limit(scope: str, max_hits: int, window_seconds: int):
        def enforce(
            request: Request,
            db: Annotated[Session, Depends(get_db)],
        ) -> None:
            forwarded_ip = request.headers.get("x-real-ip", "")
            client_ip = forwarded_ip.strip() or (
                request.client.host if request.client is not None else "unknown"
            )
            digest = hmac.new(
                settings.jwt_secret_key.encode("utf-8"),
                f"{scope}:{client_ip}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            window_start = int(datetime.now(timezone.utc).timestamp()) // window_seconds
            window_start *= window_seconds
            values = {
                "key_hash": digest,
                "window_start": window_start,
                "hits": 1,
            }
            dialect = db.get_bind().dialect.name
            if dialect == "postgresql":
                from sqlalchemy.dialects.postgresql import insert
            else:
                from sqlalchemy.dialects.sqlite import insert
            statement = insert(RateLimitBucket).values(**values)
            statement = statement.on_conflict_do_update(
                index_elements=[RateLimitBucket.key_hash],
                set_={
                    "window_start": window_start,
                    "hits": case(
                        (
                            RateLimitBucket.window_start == window_start,
                            RateLimitBucket.hits + 1,
                        ),
                        else_=1,
                    ),
                },
            ).returning(RateLimitBucket.hits)
            hits = db.scalar(statement)
            db.commit()
            if hits == 1 and window_start % 3600 < window_seconds:
                db.execute(
                    delete(RateLimitBucket).where(
                        RateLimitBucket.window_start < window_start - window_seconds * 2
                    )
                )
                db.commit()
            if hits is not None and hits > max_hits:
                raise HTTPException(
                    status_code=429,
                    detail="Too many requests. Wait and try again.",
                    headers={"Retry-After": str(window_seconds)},
                )

        return enforce

    def consume_one_time_token(
        db: Session,
        token: str,
        purpose: str,
    ) -> tuple[OneTimeToken, User] | None:
        token_hash = digest_token(token)
        record = db.scalar(
            select(OneTimeToken)
            .where(OneTimeToken.token_hash == token_hash)
            .with_for_update()
        )
        now = utcnow()
        if (
            record is None
            or record.purpose != purpose
            or record.expires_at.replace(tzinfo=timezone.utc) <= now
        ):
            return None
        user = db.get(User, record.user_id)
        if user is None:
            return None
        db.delete(record)
        return record, user

    def send_verification_email(db: Session, user: User) -> None:
        token = issue_one_time_token(
            db,
            user,
            "verify",
            utcnow() + timedelta(hours=settings.verification_token_hours),
        )
        link = f"{settings.frontend_url.rstrip('/')}/#verify={token}"
        send_account_email(
            user.email,
            "Verify your AgentShield account",
            link,
            "Verify your email address to activate your account.",
        )

    def get_current_user(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
        db: Annotated[Session, Depends(get_db)],
    ) -> User:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Authentication required.")
        try:
            claims = decode_access_token(credentials.credentials)
            user = db.get(User, claims["sub"])
            if (
                user is None
                or not user.is_verified
                or user.token_version != claims["tv"]
            ):
                raise ValueError("Token is no longer valid.")
            return user
        except (InvalidTokenError, KeyError, TypeError, ValueError) as exc:
            logger.info("Rejected invalid access token: %s", type(exc).__name__)
            raise HTTPException(status_code=401, detail="Invalid or expired access token.") from exc

    @app.post("/api/auth/register", status_code=202)
    def register(
        payload: RegisterRequest,
        db: Annotated[Session, Depends(get_db)],
        _limit: Annotated[None, Depends(rate_limit("register", 5, 3600))],
    ):
        try:
            validate_password(payload.password)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        password_hash = hash_password(payload.password)
        if db.scalar(select(User.id).where(User.email == payload.email)):
            return {"message": "If the address can be registered, a verification email will be sent."}

        tenant = Tenant(id=str(uuid4()), name=payload.email.split("@", 1)[0][:120])
        user = User(
            id=str(uuid4()),
            tenant_id=tenant.id,
            email=payload.email,
            password_hash=password_hash,
            is_verified=False,
        )
        db.add_all([tenant, user])
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return {"message": "If the address can be registered, a verification email will be sent."}
        send_verification_email(db, user)
        return {"message": "If the address can be registered, a verification email will be sent."}

    @app.post("/api/auth/verify-email", status_code=204)
    def verify_email(payload: TokenRequest, db: Annotated[Session, Depends(get_db)]):
        consumed = consume_one_time_token(db, payload.token, "verify")
        if consumed is None:
            raise HTTPException(status_code=400, detail="Verification link is invalid or expired.")
        _, user = consumed
        user.is_verified = True
        db.commit()
        return Response(status_code=204)

    @app.post("/api/auth/resend-verification", status_code=202)
    def resend_verification(
        payload: EmailRequest,
        db: Annotated[Session, Depends(get_db)],
        _limit: Annotated[None, Depends(rate_limit("verification", 3, 3600))],
    ):
        user = db.scalar(select(User).where(User.email == payload.email))
        if user is not None and not user.is_verified:
            send_verification_email(db, user)
        return {"message": "If the address needs verification, a new email will be sent."}

    @app.post("/api/auth/login")
    def login(
        payload: LoginRequest,
        db: Annotated[Session, Depends(get_db)],
        _limit: Annotated[None, Depends(rate_limit("login", 10, 300))],
    ):
        user = db.scalar(select(User).where(User.email == payload.email))
        password_hash = user.password_hash if user is not None else dummy_password_hash()
        valid = verify_password(password_hash, payload.password)
        if user is None or not valid:
            raise HTTPException(status_code=401, detail="Email or password is incorrect.")
        if not user.is_verified:
            raise HTTPException(
                status_code=403,
                detail="Verify your email address before signing in.",
            )
        return {
            "access_token": create_access_token(user.id, user.token_version),
            "token_type": "bearer",
            "expires_in": settings.access_token_minutes * 60,
        }

    @app.post("/api/auth/password-reset/request", status_code=202)
    def request_password_reset(
        payload: EmailRequest,
        db: Annotated[Session, Depends(get_db)],
        _limit: Annotated[None, Depends(rate_limit("password-reset", 3, 3600))],
    ):
        user = db.scalar(select(User).where(User.email == payload.email))
        if user is not None and user.is_verified:
            token = issue_one_time_token(
                db,
                user,
                "reset",
                utcnow() + timedelta(minutes=settings.password_reset_token_minutes),
            )
            link = f"{settings.frontend_url.rstrip('/')}/#reset={token}"
            send_account_email(
                user.email,
                "Reset your AgentShield password",
                link,
                "A password reset was requested for your account.",
            )
        return {"message": "If the account exists, password reset instructions will be sent."}

    @app.post("/api/auth/password-reset/confirm", status_code=204)
    def confirm_password_reset(
        payload: PasswordResetRequest,
        db: Annotated[Session, Depends(get_db)],
        _limit: Annotated[None, Depends(rate_limit("password-reset-confirm", 5, 3600))],
    ):
        try:
            validate_password(payload.password)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        consumed = consume_one_time_token(db, payload.token, "reset")
        if consumed is None:
            raise HTTPException(status_code=400, detail="Reset link is invalid or expired.")
        _, user = consumed
        user.password_hash = hash_password(payload.password)
        user.token_version += 1
        db.query(OneTimeToken).filter(OneTimeToken.user_id == user.id).delete(
            synchronize_session=False
        )
        db.commit()
        return Response(status_code=204)

    @app.get("/api/me")
    def current_user(user: Annotated[User, Depends(get_current_user)]):
        return {"id": user.id, "tenant_id": user.tenant_id, "email": user.email}

    @app.delete("/api/account", status_code=204)
    def delete_account(
        payload: DeleteAccountRequest,
        user: Annotated[User, Depends(get_current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        if not verify_password(user.password_hash, payload.password):
            raise HTTPException(status_code=401, detail="Password is incorrect.")
        active = db.scalar(
            select(func.count()).select_from(Scan).where(
                Scan.tenant_id == user.tenant_id,
                Scan.status.in_(("pending", "running")),
            )
        )
        if active:
            raise HTTPException(
                status_code=409,
                detail="Wait for active scans to finish before deleting this account.",
            )
        db.execute(delete(Scan).where(Scan.tenant_id == user.tenant_id))
        db.execute(delete(OneTimeToken).where(OneTimeToken.user_id == user.id))
        tenant = db.get(Tenant, user.tenant_id)
        db.delete(user)
        if tenant is not None:
            db.delete(tenant)
        db.commit()
        return Response(status_code=204)

    @app.post("/api/scans", response_model=ScanResponse, status_code=202)
    def create_scan(
        payload: ScanCreateRequest,
        user: Annotated[User, Depends(get_current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        if not payload.authorized:
            raise HTTPException(
                status_code=400,
                detail="Confirm that you own or are authorized to test this agent.",
            )
        try:
            target_url = validate_target_url(payload.endpoint_url)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        active = db.scalar(
            select(func.count())
            .select_from(Scan)
            .where(
                Scan.tenant_id == user.tenant_id,
                Scan.status.in_(("pending", "running")),
            )
        )
        if active >= settings.max_active_scans_per_tenant:
            raise HTTPException(
                status_code=429,
                detail="This workspace already has the maximum number of active scans.",
            )
        scans_today = db.scalar(
            select(func.count())
            .select_from(Scan)
            .where(
                Scan.tenant_id == user.tenant_id,
                Scan.created_at >= utcnow() - timedelta(days=1),
            )
        )
        if scans_today >= settings.max_scans_per_tenant_per_day:
            raise HTTPException(
                status_code=429,
                detail="This workspace reached its daily scan limit.",
            )

        scan = Scan(
            id=str(uuid4()),
            tenant_id=user.tenant_id,
            created_by=user.id,
            name=payload.name,
            target_url=target_url,
            model=payload.model,
            encrypted_api_key=encrypt_secret(payload.api_key),
            status="pending",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return _scan_response(scan)

    @app.get("/api/scans", response_model=list[ScanResponse])
    def list_scans(
        user: Annotated[User, Depends(get_current_user)],
        db: Annotated[Session, Depends(get_db)],
        limit: int = Query(default=50, ge=1, le=100),
    ):
        scans = db.scalars(
            select(Scan)
            .where(Scan.tenant_id == user.tenant_id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
        ).all()
        return [_scan_response(scan) for scan in scans]

    @app.get("/api/scans/{scan_id}", response_model=ScanResponse)
    def get_scan(
        scan_id: str,
        user: Annotated[User, Depends(get_current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        scan = db.scalar(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.tenant_id == user.tenant_id,
            )
        )
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return _scan_response(scan)

    @app.delete("/api/scans/{scan_id}", status_code=204)
    def delete_scan(
        scan_id: str,
        user: Annotated[User, Depends(get_current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        scan = db.scalar(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.tenant_id == user.tenant_id,
            )
        )
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        if scan.status in {"pending", "running"}:
            raise HTTPException(
                status_code=409,
                detail="Active scans cannot be deleted.",
            )
        db.delete(scan)
        db.commit()
        return Response(status_code=204)

    return app


def _scan_response(scan: Scan) -> ScanResponse:
    report = json.loads(scan.report_json) if scan.report_json else None
    return ScanResponse(
        id=scan.id,
        name=scan.name,
        target_url=scan.target_url,
        model=scan.model,
        status=scan.status,
        error_message=scan.error_message,
        report=report,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


app = create_app()
