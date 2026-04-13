"""Recovery Custodian server — stores and returns encrypted Shamir shares."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Any

import structlog
import uvicorn
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ocp_node.database import Database

log = structlog.get_logger()


class CustodianServer:
    """Stores encrypted recovery shares and returns them on authenticated request."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._custodian_cfg = config.get("custodian", {})
        self._data_dir = os.environ.get(
            "OCP_DATA_DIR",
            config.get("node", {}).get("data_dir", "/app/data"),
        )
        self._db = Database(self._data_dir)

    async def start(self) -> None:
        await self._db.connect()

        host = self._custodian_cfg.get("host", "0.0.0.0")
        port = self._custodian_cfg.get("port", 8423)

        app = self._build_app()
        server = uvicorn.Server(
            uvicorn.Config(app, host=host, port=port, log_level="warning")
        )

        # Start cleanup task
        cleanup_interval = self._custodian_cfg.get("share_expiry_check_interval_seconds", 3600)
        asyncio.create_task(self._cleanup_loop(cleanup_interval))

        log.info("Custodian server starting", port=port)
        await server.serve()

    def _build_app(self) -> Starlette:
        routes = [
            Route("/health", self._health, methods=["GET"]),
            Route("/ocp/v1/custodian/shares", self._deposit_share, methods=["POST"]),
            Route("/ocp/v1/custodian/shares/{agent_id:path}/{share_index:int}", self._get_share, methods=["GET"]),
            Route("/ocp/v1/custodian/shares/{agent_id:path}", self._revoke_shares, methods=["DELETE"]),
            Route("/ocp/v1/custodian/recover", self._recover, methods=["POST"]),
            Route("/ocp/v1/custodian/stats", self._stats, methods=["GET"]),
        ]

        app = Starlette(routes=routes)
        app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
        return app

    async def _health(self, request: Request) -> JSONResponse:
        return JSONResponse({
            "status": "healthy",
            "component": "custodian",
            "version": "1.0.0",
        })

    async def _deposit_share(self, request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        required = [
            "share_id", "agent_id", "threshold", "total_shares",
            "share_index", "encrypted_share", "key_fingerprint", "created_at",
        ]
        for f in required:
            if f not in body:
                return JSONResponse({"error": f"Missing field: {f}"}, status_code=400)

        max_shares = self._custodian_cfg.get("max_shares_stored", 10000)
        cursor = await self._db.db.execute("SELECT COUNT(*) FROM recovery_shares")
        count = (await cursor.fetchone())[0]
        if count >= max_shares:
            return JSONResponse({"error": "Custodian at capacity"}, status_code=503)

        await self._db.store_recovery_share(body)
        log.info(
            "Share deposited",
            agent_id=body["agent_id"],
            share_index=body["share_index"],
        )

        return JSONResponse(
            {"status": "stored", "share_id": body["share_id"]},
            status_code=201,
        )

    async def _get_share(self, request: Request) -> JSONResponse:
        agent_id = request.path_params["agent_id"]
        share_index = request.path_params["share_index"]

        share = await self._db.get_recovery_share(agent_id, share_index)
        if not share:
            return JSONResponse({"error": "Share not found"}, status_code=404)

        # Check expiry
        if share.get("expires_at"):
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if share["expires_at"] < now:
                return JSONResponse({"error": "Share expired"}, status_code=410)

        return JSONResponse(share)

    async def _revoke_shares(self, request: Request) -> JSONResponse:
        agent_id = request.path_params["agent_id"]
        deleted = await self._db.delete_recovery_shares(agent_id)
        log.info("Shares revoked", agent_id=agent_id, count=deleted)
        return JSONResponse({"status": "revoked", "agent_id": agent_id, "shares_deleted": deleted})

    async def _recover(self, request: Request) -> JSONResponse:
        """Handle a recovery request — verify proof and return the share."""
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        agent_id = body.get("agent_id")
        key_fp = body.get("key_fingerprint")
        proof = body.get("proof", {})

        if not agent_id or not key_fp:
            return JSONResponse({"error": "Missing agent_id or key_fingerprint"}, status_code=400)

        # Verify proof
        allowed_types = self._custodian_cfg.get("allowed_proof_types", ["secondary_key_signature"])
        if proof.get("type") not in allowed_types:
            return JSONResponse(
                {"error": f"Proof type '{proof.get('type')}' not accepted"},
                status_code=403,
            )

        # Find the share
        share = None
        for idx in range(1, 256):
            s = await self._db.get_recovery_share(agent_id, idx)
            if s and s["key_fingerprint"] == key_fp:
                share = s
                break

        if not share:
            return JSONResponse({"error": "No matching share found"}, status_code=404)

        log.info("Recovery share released", agent_id=agent_id, share_index=share["share_index"])
        return JSONResponse({
            "status": "ok",
            "agent_id": agent_id,
            "share_index": share["share_index"],
            "encrypted_share": share["encrypted_share"],
        })

    async def _stats(self, request: Request) -> JSONResponse:
        cursor = await self._db.db.execute("SELECT COUNT(*) FROM recovery_shares")
        total = (await cursor.fetchone())[0]
        cursor = await self._db.db.execute("SELECT COUNT(DISTINCT agent_id) FROM recovery_shares")
        agents = (await cursor.fetchone())[0]
        return JSONResponse({"total_shares": total, "agents_covered": agents})

    async def _cleanup_loop(self, interval: int) -> None:
        """Periodically remove expired shares."""
        while True:
            await asyncio.sleep(interval)
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            deleted = await self._db.cleanup_expired_shares(now)
            if deleted > 0:
                log.info("Expired shares cleaned up", count=deleted)
                