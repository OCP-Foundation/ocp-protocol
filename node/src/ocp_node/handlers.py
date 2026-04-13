"""Message handlers for all OCP message types.

Each handler processes a specific message_type and returns an optional
response dict. Handlers are registered with the MessageRouter.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import structlog

from ocp_node.database import Database

log = structlog.get_logger()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- Discovery ----

async def handle_discovery_ping(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    sender = msg["sender"]["agent_id"]
    payload = msg.get("payload", {})
    await db.db.execute(
        "UPDATE agents SET last_seen_at = ? WHERE agent_id = ?",
        (_now_iso(), sender),
    )
    await db.db.commit()
    log.info("Discovery ping", agent=sender, capabilities=payload.get("capabilities"))
    return {"status": "ok", "message": "Ping received"}


async def handle_capability_query(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    target = msg["receiver"]["agent_id"]
    agent = await db.get_agent(target)
    if not agent:
        return {"status": "error", "error": {"error_code": "OCP-404", "message": "Agent not found"}}
    return {
        "status": "ok",
        "payload": {
            "capabilities": agent["capabilities"],
            "domains": agent["domains"],
            "trust_level": agent["trust_level"],
        },
    }


# ---- Bond lifecycle ----

async def handle_bond_request(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    sender = msg["sender"]["agent_id"]
    receiver = msg["receiver"]["agent_id"]
    payload = msg["payload"]

    log.info("Bond request", from_agent=sender, to_agent=receiver)
    return {
        "status": "ok",
        "message": "Bond request received",
        "bond_request": {
            "from": sender,
            "to": receiver,
            "proposed_permissions": payload.get("proposed_permissions"),
            "proposed_duration_days": payload.get("proposed_duration_days", 180),
        },
    }


async def handle_bond_accept(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    payload = msg["payload"]
    bond_id = payload.get("bond_id", "")
    sender = msg["sender"]["agent_id"]
    receiver = msg["receiver"]["agent_id"]

    bond_record = {
        "bond_id": bond_id,
        "agents": [receiver, sender],
        "permissions": payload.get("agreed_permissions", {}),
        "established_at": _now_iso(),
        "expires_at": payload.get("expires_at", ""),
        "renewal": "manual",
        "signatures": payload.get("signatures", {}),
    }
    await db.upsert_bond(bond_record)
    await db.log_interaction(sender, receiver, "bond_accept", 1.0, _now_iso())

    log.info("Bond established", bond_id=bond_id, agents=[sender, receiver])
    return {"status": "ok", "bond_id": bond_id}


async def handle_bond_revoke(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    payload = msg["payload"]
    bond_id = payload.get("bond_id", "")
    revoked_by = msg["sender"]["agent_id"]

    success = await db.revoke_bond(bond_id, revoked_by, _now_iso())
    if success:
        log.info("Bond revoked", bond_id=bond_id, by=revoked_by)
        return {"status": "ok", "bond_id": bond_id, "revoked": True}
    return {"status": "error", "error": {"error_code": "OCP-404", "message": "Bond not found"}}


# ---- Knowledge ----

async def handle_knowledge_share(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    sender = msg["sender"]["agent_id"]
    receiver = msg["receiver"]["agent_id"]
    payload = msg["payload"]
    k_type = payload.get("knowledge_type", "unknown")

    await db.log_interaction(sender, receiver, "knowledge_share", None, _now_iso())
    log.info("Knowledge shared", type=k_type, from_agent=sender, to_agent=receiver)

    return {
        "status": "ok",
        "message": f"Knowledge ({k_type}) accepted",
        "knowledge_id": payload.get("insight_id") or payload.get("delta_id") or "unknown",
    }


# ---- Tasks ----

async def handle_task_request(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    sender = msg["sender"]["agent_id"]
    receiver = msg["receiver"]["agent_id"]
    payload = msg["payload"]

    task_record = {
        "task_id": payload["task_id"],
        "requester": sender,
        "receiver": receiver,
        "task_type": payload["task_type"],
        "description": payload.get("description", ""),
        "input": payload.get("input", {}),
        "constraints": payload.get("constraints", {}),
        "created_at": _now_iso(),
    }
    await db.insert_task(task_record)

    log.info("Task received", task_id=payload["task_id"], type=payload["task_type"])
    return {
        "status": "ok",
        "payload": {"task_id": payload["task_id"], "status": "accepted"},
    }


async def handle_task_response(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    payload = msg["payload"]
    task_id = payload["task_id"]
    status = payload["status"]

    await db.update_task_status(
        task_id,
        status,
        result=payload.get("result"),
        error=payload.get("error"),
        execution_metadata=payload.get("execution_metadata"),
    )

    if status == "completed":
        sender = msg["sender"]["agent_id"]
        task = await db.get_task(task_id)
        if task:
            await db.log_interaction(sender, task["requester"], "task_complete", 1.0, _now_iso())

    log.info("Task updated", task_id=task_id, status=status)
    return {"status": "ok", "task_id": task_id}


# ---- Consensus ----

async def handle_consensus_initiate(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    sender = msg["sender"]["agent_id"]
    payload = msg["payload"]

    round_data = {
        "consensus_id": payload["consensus_id"],
        "initiator": sender,
        "topic": payload["topic"],
        "options": payload["options"],
        "quorum": payload["quorum"],
        "eligible_agents": payload.get("eligible_agents"),
        "deadline": payload.get("deadline"),
        "created_at": _now_iso(),
    }
    await db.insert_consensus_round(round_data)

    log.info("Consensus initiated", id=payload["consensus_id"], topic=payload["topic"])
    return {"status": "ok", "consensus_id": payload["consensus_id"]}


async def handle_consensus_vote(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    sender = msg["sender"]["agent_id"]
    payload = msg["payload"]

    # Fetch agent trust score
    agent = await db.get_agent(sender)
    trust_score = agent["trust_score"] if agent else 0.0

    vote = {
        "consensus_id": payload["consensus_id"],
        "voter_id": sender,
        "vote": payload["vote"],
        "confidence": payload["confidence"],
        "trust_score": trust_score,
        "rationale_hash": payload.get("rationale_hash"),
        "signature": payload.get("signature"),
        "voted_at": _now_iso(),
    }
    accepted = await db.insert_consensus_vote(vote)

    if not accepted:
        return {"status": "error", "error": {"error_code": "OCP-400", "message": "Duplicate vote"}}

    log.info("Vote recorded", consensus_id=payload["consensus_id"], voter=sender)
    return {"status": "ok", "consensus_id": payload["consensus_id"], "vote_accepted": True}


# ---- Recovery ----

async def handle_recovery_request(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    payload = msg["payload"]
    agent_id = payload["agent_id"]
    key_fp = payload["key_fingerprint"]

    # Look up the share for this agent
    # The custodian holds one share per agent
    share = None
    for idx in range(1, 256):
        s = await db.get_recovery_share(agent_id, idx)
        if s and s["key_fingerprint"] == key_fp:
            share = s
            break

    if not share:
        log.warning("Recovery share not found", agent_id=agent_id)
        return {"status": "error", "error": {"error_code": "OCP-404", "message": "Share not found"}}

    log.info("Recovery share returned", agent_id=agent_id, share_index=share["share_index"])
    return {
        "status": "ok",
        "payload": {
            "agent_id": agent_id,
            "share_index": share["share_index"],
            "encrypted_share": share["encrypted_share"],
            "nonce": "",  # Already included in the encrypted blob
        },
    }


async def handle_share_revoke(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    sender = msg["sender"]["agent_id"]
    deleted = await db.delete_recovery_shares(sender)
    log.info("Recovery shares revoked", agent_id=sender, count=deleted)
    return {"status": "ok", "shares_deleted": deleted}


# ---- Generic ----

async def handle_ack(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    log.debug("ACK received", for_message=msg["payload"].get("acknowledged_message_id"))
    return {}


async def handle_broadcast(msg: dict[str, Any], source: str, db: Database) -> dict[str, Any]:
    sender = msg["sender"]["agent_id"]
    tags = msg.get("metadata", {}).get("tags", [])
    log.info("Broadcast received", from_agent=sender, tags=tags)
    return {"status": "ok", "message": "Broadcast received"}


def register_all_handlers(router: Any, db: Database) -> None:
    """Register all message handlers with the router."""
    def _wrap(fn: Any) -> Any:
        async def wrapper(msg: dict, source: str) -> dict:
            return await fn(msg, source, db)
        return wrapper

    router.register_handler("discovery_ping", _wrap(handle_discovery_ping))
    router.register_handler("capability_query", _wrap(handle_capability_query))
    router.register_handler("capability_response", _wrap(handle_ack))
    router.register_handler("knowledge_share", _wrap(handle_knowledge_share))
    router.register_handler("knowledge_ack", _wrap(handle_ack))
    router.register_handler("task_request", _wrap(handle_task_request))
    router.register_handler("task_response", _wrap(handle_task_response))
    router.register_handler("bond_request", _wrap(handle_bond_request))
    router.register_handler("bond_negotiate", _wrap(handle_bond_request))
    router.register_handler("bond_accept", _wrap(handle_bond_accept))
    router.register_handler("bond_confirm", _wrap(handle_ack))
    router.register_handler("bond_revoke", _wrap(handle_bond_revoke))
    router.register_handler("consensus_initiate", _wrap(handle_consensus_initiate))
    router.register_handler("consensus_vote", _wrap(handle_consensus_vote))
    router.register_handler("consensus_result", _wrap(handle_ack))
    router.register_handler("broadcast", _wrap(handle_broadcast))
    router.register_handler("recovery_request", _wrap(handle_recovery_request))
    router.register_handler("recovery_share_response", _wrap(handle_ack))
    router.register_handler("share_revoke", _wrap(handle_share_revoke))
    router.register_handler("ack", _wrap(handle_ack))
    router.register_handler("error", _wrap(handle_ack))
