"""WSGI entry point.

Run locally:
    python wsgi.py            # dev server on http://127.0.0.1:5000
"""
from __future__ import annotations

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # host 0.0.0.0 is intentional for the Docker image; keep it local otherwise.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=False)
