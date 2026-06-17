"""sift — transparent, self-hosted alert triage."""

from .server import main
from .routes import Handler

__all__ = ["main", "Handler"]
