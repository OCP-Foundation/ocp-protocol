"""Message router — validates, deduplicates, and dispatches OCPUMF messages.

This is the core routing engine of the OCP node. Every inbound message
passes through:
  1. Structural validation
  2. Deduplication check
  3. TTL/expiry check
  4. PVL enforcement (for knowledge_share)
  5. Trust level verification
  6. Dispatch to the appropriate handler
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Awaitable

import structlog

from ocp.constants import OCP_VERSION
from ocp.messages import MessageValidator, is_expired
from ocp.pvl import validate_knowledge_payload
from ocp_node.database import Database

log = structlog.get_logger()

Handler = Callable[[dict[str, Any], str], Awaitable[dict[str, Any] | None]]


class MessageRouter:
    """Routes inbound OCPUMF messages to registered handlers."""

    def __init__(self, db: Database, config: dict[str, Any]) -> None:
        self._db = db
        self._config = config
        self._validator = MessageValidator()
        self._handlers: dict[str, Handler] = {}

    def register_handler(self, message_type: str, handler: Handler) -> None:
        self._handlers[message_type] = handler
        log.debug("Handler registered", message_type=message_type)

    async def route(self, raw: dict[str, Any], source: str = "http") -> dict[str, Any]:
        """Route an inbound message through validation and dispatch.

        Args:
            raw: Parsed OCPUMF message dict.
            source: Transport source identifier.

        Returns:
            Response dict (may be empty for async processing).
        """
        msg_id = raw.get("message_id", "unknown")
        msg_type = raw.get("message_type", "unknown")

        # 1. Structural validation
        try:
            self._validator.validate_structure(raw)
        except Exception as e:
            log.warning("Validation failed", message_id=msg_id, error=str(e))
            return self._error_response("OCP-400", str(e), msg_id)

        # 2. Deduplication
        now = datetime.now(timezone.utc)
        ttl = raw.get("ttl", 3600)
        expires = (now + timedelta(seconds=max(ttl, 3600))).strftime("%Y-%m-%dT%H:%M:%SZ")
        is_new = await self._db.check_and_record_message(
            msg_id, now.strftime("%Y-%m-%dT%H:%M:%SZ"), expires
        )
        if not is_new:
            log.debug("Duplicate message dropped", message_id=msg_id)
            return self._error_response("OCP-400", "Duplicate message", msg_id)

        # 3. Expiry check
        if is_expired(raw):
            log.debug("Expired message dropped", message_id=msg_id)
            return self._error_response("OCP-408", "Message expired", msg_id)

        # 4. PVL enforcement for knowledge_share
        if msg_type == "knowledge_share":
            pvl_result = validate_knowledge_payload(
                raw.get("payload", {}),
                self._config.get("knowledge", {}).get("max_payload_bytes", 10_485_760),
            )
            sender = raw.get("sender", {}).get("agent_id", "unknown")
            receiver = raw.get("receiver", {}).get("agent_id", "unknown")

            await self._db.log_knowledge_exchange({
                "knowledge_type": raw.get("payload", {}).get("knowledge_type", "unknown"),
                "knowledge_id": raw.get("payload", {}).get("insight_id")
                    or raw.get("payload", {}).get("delta_id")
                    or "unknown",
                "sender": sender,
                "receiver": receiver,
                "topic": raw.get("payload", {}).get("topic"),
                "confidence": raw.get("payload", {}).get("confidence"),
                "pvl_passed": pvl_result.passed,
                "pvl_code": pvl_result.rejection_code,
                "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })

            if not pvl_result.passed:
                log.warning(
                    "PVL rejected knowledge",
                    message_id=msg_id,
                    pvl_code=pvl_result.rejection_code,
                )
                return self._error_response(
                    "OCP-403",
                    f"PVL rejection: {pvl_result.rejection_reason}",
                    msg_id,
                    details={"pvl_code": pvl_result.rejection_code},
                )

        # 5. Dispatch to handler
        handler = self._handlers.get(msg_type)
        if handler:
            try:
                result = await handler(raw, source)
                log.info("Message processed", message_id=msg_id, type=msg_type)
                return result or {}
            except Exception as e:
                log.error("Handler error", message_id=msg_id, type=msg_type, error=str(e))
                return self._error_response("OCP-500", f"Internal error: {e}", msg_id)
        else:
            log.warning("No handler for message type", type=msg_type)
            return self._error_response("OCP-400", f"Unhandled message type: {msg_type}", msg_id)

    def _error_response(
        self, code: str, message: str, ref_id: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        resp: dict[str, Any] = {
            "ocp_version": OCP_VERSION,
            "status": "error",
            "error": {
                "error_code": code,
                "message": message,
                "reference_message_id": ref_id,
            },
        }
        if details:
            resp["error"]["details"] = details
        return resp
        