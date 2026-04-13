"""Agent Registry server — registration, discovery, and resolution."""

from __future__ import annotations

import os
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


class RegistryServer:
    """Serves the OCP Agent Registry API."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._data_dir = os.environ.get(
            "OCP_DATA_DIR",
            config.get("node", {}).get("data_dir", "/app/data"),
        )
        self._db = Database(self._data_dir)

    async def start(self) -> None:
        await self._db.connect()

        reg_cfg = self._config.get("registry", {})
        host = reg_cfg.get("host", "0.0.0.0")
        port = reg_cfg.get("port", 8422)

        app = self._build_app()
        server = uvicorn.Server(
            uvicorn.Config(app, host=host, port=port, log_level="warning")
        )
        log.info("Registry server starting", port=port)
        await server.serve()

    def _build_app(self) -> Starlette:
        routes = [
            Route("/health", self._health, methods=["GET"]),
            Route("/ocp/v1/registry/agents", self._register_agent, methods=["POST"]),
            Route("/ocp/v1/registry/agents/{agent_id:path}", self._get_agent, methods=["GET"]),
            Route("/ocp/v1/registry/agents/{agent_id:path}", self._delete_agent, methods=["DELETE"]),
            Route("/ocp/v1/registry/discover", self._discover, methods=["POST"]),
            Route("/ocp/v1/registry/vouches", self._submit_vouch, methods=["POST"]),
            Route("/ocp/v1/registry/agents/{agent_id:path}/vouches", self._get_vouches, methods=["GET"]),
            Route("/ocp/v1/registry/stats", self._stats, methods=["GET"]),
        ]

        app = Starlette(routes=routes)
        app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
        return app

    async def _health(self, request: Request) -> JSONResponse:
        return JSONResponse({
            "status": "healthy",
            "component": "registry",
            "version": "1.0.0",
        })

    async def _register_agent(self, request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        required = ["agent_id", "display_name", "capabilities", "domains", "endpoints"]
        for f in required:
            if f not in body:
                return JSONResponse({"error": f"Missing field: {f}"}, status_code=400)

        from datetime import datetime, timezone
        body.setdefault("version", "1.0.0")
        body.setdefault("status", "active")
        body.setdefault("registered_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        body.setdefault("last_seen_at", body["registered_at"])
        body.setdefault("ttl", 86400)
        body.setdefault("signature", "")

        await self._db.upsert_agent(body)
        log.info("Agent registered", agent_id=body["agent_id"], name=body["display_name"])

        return JSONResponse(
            {"status": "registered", "agent_id": body["agent_id"]},
            status_code=201,
        )

    async def _get_agent(self, request: Request) -> JSONResponse:
        agent_id = request.path_params["agent_id"]
        agent = await self._db.get_agent(agent_id)
        if not agent:
            return JSONResponse({"error": "Agent not found"}, status_code=404)
        return JSONResponse(agent)

    async def _delete_agent(self, request: Request) -> JSONResponse:
        agent_id = request.path_params["agent_id"]
        deleted = await self._db.delete_agent(agent_id)
        if not deleted:
            return JSONResponse({"error": "Agent not found"}, status_code=404)
        return JSONResponse({"status": "deleted", "agent_id": agent_id})

    async def _discover(self, request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        filters = body.get("filters", {})
        limit = min(body.get("limit", 20), 100)
        offset = body.get("offset", 0)

        total, results = await self._db.discover_agents(
            domains=filters.get("domains"),
            capabilities=filters.get("capabilities"),
            min_trust_level=filters.get("min_trust_level", 0),
            status=filters.get("status", "active"),
            limit=limit,
            offset=offset,
        )

        return JSONResponse({
            "total": total,
            "limit": limit,
            "offset": offset,
            "results": results,
        })

    async def _submit_vouch(self, request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        required = ["attester", "subject", "domains", "issued_at", "expires_at"]
        for f in required:
            if f not in body:
                return JSONResponse({"error": f"Missing field: {f}"}, status_code=400)

        if body["attester"] == body["subject"]:
            return JSONResponse({"error": "Self-vouching prohibited"}, status_code=400)

        vouch_id = await self._db.insert_vouch(body)

        # Check if subject now qualifies for Level 2
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        count = await self._db.count_valid_vouches(body["subject"], now)
        threshold = self._config.get("trust", {}).get("vouches_required_for_level2", 3)

        if count >= threshold:
            await self._db.db.execute(
                "UPDATE agents SET trust_level = MAX(trust_level, 2) WHERE agent_id = ?",
                (body["subject"],),
            )
            await self._db.db.commit()
            log.info("Agent promoted to Level 2", agent_id=body["subject"], vouches=count)

        return JSONResponse({"status": "accepted", "vouch_id": vouch_id}, status_code=201)

    async def _get_vouches(self, request: Request) -> JSONResponse:
        agent_id = request.path_params["agent_id"]
        vouches = await self._db.get_vouches_for_agent(agent_id)
        return JSONResponse({"agent_id": agent_id, "vouches": vouches})

    async def _stats(self, request: Request) -> JSONResponse:
        cursor = await self._db.db.execute("SELECT COUNT(*) FROM agents WHERE status='active'")
        agents = (await cursor.fetchone())[0]
        cursor = await self._db.db.execute("SELECT COUNT(*) FROM bonds WHERE revoked=0")
        bonds = (await cursor.fetchone())[0]
        cursor = await self._db.db.execute("SELECT COUNT(*) FROM vouches WHERE revoked=0")
        vouches = (await cursor.fetchone())[0]
        return JSONResponse({
            "active_agents": agents,
            "active_bonds": bonds,
            "active_vouches": vouches,
        })
