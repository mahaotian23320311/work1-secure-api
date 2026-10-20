"""Application factory for the Secure Notes API."""

from __future__ import annotations

import logging

from flask import Flask, g, request
from werkzeug.exceptions import HTTPException

from .config import load_config
from .db import close_db, init_db
from .errors import ApiError, error_response

log = logging.getLogger(__name__)


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.from_mapping(load_config())
    if overrides:
        app.config.update(overrides)

    app.teardown_appcontext(close_db)
    init_db(app)

    from .api import api_bp
    from .auth import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    @app.before_request
    def only_json_api():
        # This service is a JSON API, nothing else. Refusing form posts removes
        # a whole class of CSRF/parser tricks and keeps responses non-HTML.
        if request.path.startswith(("/auth", "/api")) and request.method in {"POST", "PUT", "PATCH"}:
            if not request.is_json:
                return error_response(415, "unsupported_media_type", "Content-Type must be application/json.")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        if request.path.startswith(("/auth", "/api")):
            response.headers.setdefault("Cache-Control", "no-store")
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.errorhandler(ApiError)
    def handle_api_error(exc: ApiError):
        return error_response(exc.status, exc.code, exc.message, exc.headers)

    @app.errorhandler(HTTPException)
    def handle_http_error(exc: HTTPException):
        return error_response(exc.code or 500, exc.name.lower().replace(" ", "_"), exc.description)

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception):
        # Log the detail, return a generic 500: stack traces are an
        # information-disclosure bug (CWE-209).
        log.exception("unhandled error on %s %s", request.method, request.path)
        return error_response(500, "internal_error", "An unexpected error occurred.")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
