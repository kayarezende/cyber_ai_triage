"""Cached splunk-sdk Service factory.

Wk-2 SCOPE: single env-based connection (founder tenant only). The factory
lives behind a lock so concurrent tool calls in one container share one
authenticated session — Splunk auth is heavy enough that per-call connect()
would dominate latency.

WK-4 BOUNDARY (do not refactor before): when ingest lands per-tenant tokens,
`get(...)` will become `get(tenant_id: UUID)` and look up the Fernet-decrypted
`splunk_host` + `splunk_token_encrypted` from the `tenants` table. Tool
handlers receive a `splunklib.client.Service` and don't care where it came
from — only this file changes.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

import splunklib.client as splunk_client
from splunklib.binding import AuthenticationError

from sentient_mcp_splunk.settings import SplunkSettings

if TYPE_CHECKING:
    from splunklib.client import Service


class SplunkClientFactory:
    """Process-wide cached Splunk Service.

    `_alive()` issues a cheap `service.info` call before handing back the
    cached connection. On `AuthenticationError` we drop the cache + reconnect
    once; persistent failure surfaces to the tool layer for MCP error mapping.
    """

    _lock: threading.Lock = threading.Lock()
    _service: Service | None = None

    @classmethod
    def get(cls, settings: SplunkSettings) -> Service:
        with cls._lock:
            if cls._service is None or not cls._alive(cls._service):
                cls._service = cls._connect(settings)
            return cls._service

    @classmethod
    def reset(cls) -> None:
        """Drop the cached service. Used by tools after auth-related errors."""
        with cls._lock:
            cls._service = None

    @staticmethod
    def _connect(settings: SplunkSettings) -> Service:
        return splunk_client.connect(
            host=settings.splunk_host,
            port=settings.splunk_port,
            token=settings.splunk_token,
            verify=settings.splunk_verify_tls,
            autologin=True,
        )

    @staticmethod
    def _alive(service: Service) -> bool:
        try:
            _ = service.info
        except AuthenticationError:
            return False
        except Exception:
            return False
        return True
