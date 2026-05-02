"""Transport server — HTTP and WebSocket endpoints.

Runs both transports concurrently:
  - HTTP on port 8420 (Starlette/Uvicorn)
  - WebSocket on port 8421 (websockets library)
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import structlog
import uvicorn
import websockets
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ocp_node.database import Database
from ocp_node.handlers import register_all_handlers
from ocp_node.message_router import MessageRouter

log = structlog.get_logger()


class TransportServer:
    """Runs HTTP + WebSocket transport endpoints."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._data_dir = os.environ.get(
            "OCP_DATA_DIR",
            config.get("node", {}).get("data_dir", "/app/data"),
        )
        self._db = Database(self._data_dir)
        self._router = MessageRouter(self._db, config)
        self._ws_clients: dict[str, websockets.WebSocketServerProtocol] = {}

    async def start(self) -> None:
        await self._db.connect()
        register_all_handlers(self._router, self._db)

        http_cfg = self._config.get("transport", {}).get("http", {})
        ws_cfg = self._config.get("transport", {}).get("websocket", {})

        http_host = http_cfg.get("host", "0.0.0.0")
        http_port = http_cfg.get("port", 8420)
        ws_host = ws_cfg.get("host", "0.0.0.0")
        ws_port = ws_cfg.get("port", 8421)

        app = self._build_http_app(http_cfg)

        http_server = uvicorn.Server(
            uvicorn.Config(app, host=http_host, port=http_port, log_level="warning")
        )

        log.info("Transport server starting", http_port=http_port, ws_port=ws_port)

        await asyncio.gather(
            http_server.serve(),
            self._run_websocket(ws_host, ws_port, ws_cfg),
        )

    def _build_http_app(self, cfg: dict[str, Any]) -> Starlette:
        routes = [
            Route("/health", self._health, methods=["GET"]),
            Route("/ocp/v1/messages", self._handle_http_message, methods=["POST"]),
            Route("/ocp/v1/agents/{agent_id:path}/bonds", self._get_agent_bonds, methods=["GET"]),
            Route("/ocp/v1/agents/{agent_id:path}/tasks", self._get_agent_tasks, methods=["GET"]),
            Route("/ocp/v1/tasks/{task_id:path}", self._get_task, methods=["GET"]),
            Route("/ocp/v1/consensus/{consensus_id:path}", self._get_consensus, methods=["GET"]),
            Route("/ocp/v1/consensus/{consensus_id:path}/resolve", self._resolve_consensus, methods=["POST"]),
        ]

        app = Starlette(routes=routes)
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.get("cors_origins", ["*"]),
            allow_methods=["*"],
            allow_headers=["*"],
        )
        return app

    async def _health(self, request: Request) -> JSONResponse:
        return JSONResponse({
            "status": "healthy",
            "component": "transport",
            "version": "1.0.0",
            "network": self._config.get("node", {}).get("network", "mainnet"),
        })

    async def _handle_http_message(self, request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        result = await self._router.route(body, source="http")
        status = 200 if result.get("status") != "error" else 400
        return JSONResponse(result, status_code=status)

    async def _get_agent_bonds(self, request: Request) -> JSONResponse:
        agent_id = request.path_params["agent_id"]
        bonds = await self._db.get_bonds_for_agent(agent_id)
        return JSONResponse({"agent_id": agent_id, "bonds": bonds})

    async def _get_agent_tasks(self, request: Request) -> JSONResponse:
        agent_id = request.path_params["agent_id"]
        tasks = await self._db.get_active_tasks_for_agent(agent_id)
        return JSONResponse({"agent_id": agent_id, "tasks": tasks})

    async def _get_task(self, request: Request) -> JSONResponse:
        task_id = request.path_params["task_id"]
        task = await self._db.get_task(task_id)
        if not task:
            return JSONResponse({"error": "Task not found"}, status_code=404)
        return JSONResponse(task)

    async def _get_consensus(self, request: Request) -> JSONResponse:
        cid = request.path_params["consensus_id"]
        cr = await self._db.get_consensus_round(cid)
        if not cr:
            return JSONResponse({"error": "Consensus round not found"}, status_code=404)
        votes = await self._db.get_consensus_votes(cid)
        cr["votes"] = votes
        return JSONResponse(cr)

    async def _resolve_consensus(self, request: Request) -> JSONResponse:
        cid = request.path_params["consensus_id"]
        cr = await self._db.get_consensus_round(cid)
        if not cr:
            return JSONResponse({"error": "Not found"}, status_code=404)
        if cr["status"] == "resolved":
            return JSONResponse({"error": "Already resolved"}, status_code=400)

        votes = await self._db.get_consensus_votes(cid)
        quorum = cr["quorum"]
        options = cr["options"]

        scores = {opt: 0.0 for opt in options}
        for v in votes:
            if quorum.get("weighted", True):
                scores[v["vote"]] += v["trust_score"] * v["confidence"]
            else:
                scores[v["vote"]] += 1.0

        total = sum(scores.values())
        reached_quorum = len(votes) >= quorum.get("min_participants", 1)
        winner = None
        reached_threshold = False

        if total > 0:
            best = max(scores, key=lambda k: scores[k])
            if scores[best] / total >= quorum.get("threshold", 0.67):
                winner = best
                reached_threshold = True

        result = {
            "consensus_id": cid,
            "winner": winner if reached_quorum and reached_threshold else None,
            "weighted_scores": scores,
            "total_votes": len(votes),
            "reached_quorum": reached_quorum,
            "reached_threshold": reached_threshold,
        }
        await self._db.resolve_consensus(cid, result)
        return JSONResponse(result)

    # ---- WebSocket ----

    async def _run_websocket(self, host: str, port: int, cfg: dict[str, Any]) -> None:
        async def ws_handler(ws: websockets.WebSocketServerProtocol) -> None:
            agent_id = None
            try:
                # Auth handshake
                raw = await asyncio.wait_for(ws.recv(), timeout=cfg.get("auth_timeout_seconds", 5))
                handshake = json.loads(raw)

                if handshake.get("frame_type") != "auth_handshake":
                    await ws.close(1002, "Expected auth_handshake")
                    return

                agent_id = handshake.get("agent_id", "unknown")
                session_id = f"sess-{agent_id[-12:]}"

                await ws.send(json.dumps({
                    "frame_type": "auth_result",
                    "status": "accepted",
                    "session_id": session_id,
                    "ttl": 86400,
                }))

                self._ws_clients[agent_id] = ws
                log.info("WebSocket connected", agent=agent_id, session=session_id)

                # Message loop
                async for raw_msg in ws:
                    msg = json.loads(raw_msg)
                    result = await self._router.route(msg, source="ws")
                    if result:
                        await ws.send(json.dumps(result))

            except asyncio.TimeoutError:
                log.warning("WebSocket auth timeout")
            except websockets.exceptions.ConnectionClosed:
                pass
            except Exception as e:
                log.error("WebSocket error", error=str(e))
            finally:
                if agent_id and agent_id in self._ws_clients:
                    del self._ws_clients[agent_id]
                log.info("WebSocket disconnected", agent=agent_id)

        async with websockets.serve(ws_handler, host, port, subprotocols=["ocp.v1"]):
            await asyncio.Future()  # Run forever
