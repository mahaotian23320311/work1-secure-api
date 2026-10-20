"""Uniform JSON error responses.

Returning machine-readable error codes while keeping the human message vague
is what stops the API from confirming whether a username exists.
"""

from __future__ import annotations

from flask import jsonify


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


def error_response(status: int, code: str, message: str, headers: dict | None = None):
    response = jsonify({"error": {"code": code, "message": message}})
    response.status_code = status
    for key, value in (headers or {}).items():
        response.headers[key] = value
    return response
