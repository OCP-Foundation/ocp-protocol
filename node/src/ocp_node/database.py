"""Async SQLite database layer for persistent storage.

Stores agent records, bonds, vouches, tasks, consensus rounds,
recovery shares, and message deduplication state.
"""

from __future__ import annotations

import json
import os
from typing import Any

import aiosqlite
import structlog

log = structlog.get_logger()

_SCHEMA = """
-- Agent Registry
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    version TEXT NOT NULL,
    capabilities TEXT NOT NULL,     -- JSON array
    domains TEXT NOT NULL,          -- JSON array
    endpoints TEXT NOT NULL,        -- JSON array
    extensions TEXT DEFAULT '[]',   -- JSON array
    trust_level INTEGER DEFAULT 0,
    trust_score REAL DEFAULT 0.0,
    status TEXT DEFAULT 'active',
    did_document_url TEXT,
    registered_at TEXT NOT NULL,
    last_seen_at TEXT,
    ttl INTEGER DEFAULT 86400,
    signature TEXT NOT NULL
);

-- Bonds
CREATE TABLE IF NOT EXISTS bonds (
    bond_id TEXT PRIMARY KEY,
    agent_a TEXT NOT NULL,
    agent_b TEXT NOT NULL,
    permissions TEXT NOT NULL,      -- JSON
    established_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    renewal TEXT DEFAULT 'manual',
    revoked INTEGER DEFAULT 0,
    revoked_by TEXT,
    revoked_at TEXT,
    signature_a TEXT,
    signature_b TEXT,
    FOREIGN KEY (agent_a) REFERENCES agents(agent_id),
    FOREIGN KEY (agent_b) REFERENCES agents(agent_id)
);
CREATE INDEX IF NOT EXISTS idx_bonds_agents ON bonds(agent_a, agent_b);

-- Vouches
CREATE TABLE IF NOT EXISTS vouches (
    vouch_id INTEGER PRIMARY KEY AUTOINCREMENT,
    attester TEXT NOT NULL,
    subject TEXT NOT NULL,
    domains TEXT NOT NULL,          -- JSON array
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER DEFAULT 0,
    signature TEXT NOT NULL,
    FOREIGN KEY (attester) REFERENCES agents(agent_id),
    FOREIGN KEY (subject) REFERENCES agents(agent_id)
);
CREATE INDEX IF NOT EXISTS idx_vouches_subject ON vouches(subject);

-- Tasks
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    receiver TEXT NOT NULL,
    task_type TEXT NOT NULL,
    description TEXT,
    input_data TEXT,               -- JSON
    constraints TEXT,              -- JSON
    status TEXT DEFAULT 'pending',
    result TEXT,                   -- JSON
    error TEXT,                    -- JSON
    created_at TEXT NOT NULL,
    accepted_at TEXT,
    completed_at TEXT,
    timeout_seconds INTEGER DEFAULT 300,
    execution_metadata TEXT        -- JSON
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_requester ON tasks(requester);

-- Consensus Rounds
CREATE TABLE IF NOT EXISTS consensus_rounds (
    consensus_id TEXT PRIMARY KEY,
    initiator TEXT NOT NULL,
    topic TEXT NOT NULL,
    options TEXT NOT NULL,          -- JSON array
    quorum_config TEXT NOT NULL,    -- JSON
    eligible_agents TEXT,           -- JSON
    deadline TEXT,
    status TEXT DEFAULT 'open',    -- open | closed | resolved
    result TEXT,                    -- JSON (filled on resolution)
    created_at TEXT NOT NULL
);

-- Consensus Votes
CREATE TABLE IF NOT EXISTS consensus_votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    consensus_id TEXT NOT NULL,
    voter_id TEXT NOT NULL,
    vote TEXT NOT NULL,
    confidence REAL NOT NULL,
    trust_score REAL NOT NULL,
    rationale_hash TEXT,
    signature TEXT,
    voted_at TEXT NOT NULL,
    FOREIGN KEY (consensus_id) REFERENCES consensus_rounds(consensus_id),
    UNIQUE(consensus_id, voter_id)
);

-- Recovery Shares (Custodian storage)
CREATE TABLE IF NOT EXISTS recovery_shares (
    share_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    scheme TEXT DEFAULT 'shamir-sss-gf256',
    threshold INTEGER NOT NULL,
    total_shares INTEGER NOT NULL,
    share_index INTEGER NOT NULL,
    encrypted_share TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    custodian_key_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    UNIQUE(agent_id, share_index)
);
CREATE INDEX IF NOT EXISTS idx_shares_agent ON recovery_shares(agent_id);

-- Knowledge log (audit trail, not full payload storage)
CREATE TABLE IF NOT EXISTS knowledge_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    knowledge_type TEXT NOT NULL,
    knowledge_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    topic TEXT,
    confidence REAL,
    pvl_passed INTEGER NOT NULL,
    pvl_code TEXT,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_sender ON knowledge_log(sender);

-- Message deduplication
CREATE TABLE IF NOT EXISTS message_ids (
    message_id TEXT PRIMARY KEY,
    received_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Trust interaction log (for reputation scoring)
CREATE TABLE IF NOT EXISTS interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_agent TEXT NOT NULL,
    to_agent TEXT NOT NULL,
    interaction_type TEXT NOT NULL,  -- message | task_complete | knowledge_share | vouch
    rating REAL,                     -- 0.0 - 1.0
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_interactions_to ON interactions(to_agent);
"""


class Database:
    """Async SQLite database for the OCP node."""

    def __init__(self, data_dir: str) -> None:
        os.makedirs(data_dir, exist_ok=True)
        self._path = os.path.join(data_dir, "ocp_node.db")
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        log.info("Database connected", path=self._path)

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    @property
    def db(self) -> aiosqlite.Connection:
        assert self._db is not None, "Database not connected"
        return self._db

    # ---- Agents ----

    async def upsert_agent(self, record: dict[str, Any]) -> None:
        await self.db.execute(
            """INSERT INTO agents
               (agent_id, display_name, version, capabilities, domains,
                endpoints, extensions, trust_level, status,
                did_document_url, registered_at, last_seen_at, ttl, signature)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET
                 display_name=excluded.display_name,
                 version=excluded.version,
                 capabilities=excluded.capabilities,
                 domains=excluded.domains,
                 endpoints=excluded.endpoints,
                 extensions=excluded.extensions,
                 trust_level=excluded.trust_level,
                 status=excluded.status,
                 last_seen_at=excluded.last_seen_at,
                 ttl=excluded.ttl,
                 signature=excluded.signature
            """,
            (
                record["agent_id"],
                record["display_name"],
                record["version"],
                json.dumps(record["capabilities"]),
                json.dumps(record["domains"]),
                json.dumps(record["endpoints"]),
                json.dumps(record.get("extensions", [])),
                record.get("trust_level", 0),
                record.get("status", "active"),
                record.get("did_document_url", ""),
                record.get("registered_at", ""),
                record.get("last_seen_at"),
                record.get("ttl", 86400),
                record.get("signature", ""),
            ),
        )
        await self.db.commit()

    async def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        cursor = await self.db.execute(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return self._agent_row_to_dict(row)

    async def discover_agents(
        self,
        domains: list[str] | None = None,
        capabilities: list[str] | None = None,
        min_trust_level: int = 0,
        status: str = "active",
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[int, list[dict[str, Any]]]:
        conditions = ["status = ?"]
        params: list[Any] = [status]

        if min_trust_level > 0:
            conditions.append("trust_level >= ?")
            params.append(min_trust_level)

        where = " AND ".join(conditions)
        count_cursor = await self.db.execute(
            f"SELECT COUNT(*) FROM agents WHERE {where}", params
        )
        total = (await count_cursor.fetchone())[0]

        cursor = await self.db.execute(
            f"""SELECT * FROM agents WHERE {where}
                ORDER BY trust_level DESC, registered_at ASC
                LIMIT ? OFFSET ?""",
            params + [limit, offset],
        )
        rows = await cursor.fetchall()
        results = [self._agent_row_to_dict(r) for r in rows]

        # Post-filter by domains and capabilities (JSON contains)
        if domains:
            results = [
                r for r in results
                if any(d in r["domains"] for d in domains)
            ]
        if capabilities:
            cap_ids = set(capabilities)
            results = [
                r for r in results
                if cap_ids.intersection(c["id"] for c in r["capabilities"])
            ]

        return total, results

    async def delete_agent(self, agent_id: str) -> bool:
        cursor = await self.db.execute(
            "DELETE FROM agents WHERE agent_id = ?", (agent_id,)
        )
        await self.db.commit()
        return cursor.rowcount > 0

    def _agent_row_to_dict(self, row: aiosqlite.Row) -> dict[str, Any]:
        return {
            "agent_id": row["agent_id"],
            "display_name": row["display_name"],
            "version": row["version"],
            "capabilities": json.loads(row["capabilities"]),
            "domains": json.loads(row["domains"]),
            "endpoints": json.loads(row["endpoints"]),
            "extensions": json.loads(row["extensions"]),
            "trust_level": row["trust_level"],
            "trust_score": row["trust_score"],
            "status": row["status"],
            "did_document_url": row["did_document_url"],
            "registered_at": row["registered_at"],
            "last_seen_at": row["last_seen_at"],
            "ttl": row["ttl"],
        }

    # ---- Bonds ----

    async def upsert_bond(self, bond: dict[str, Any]) -> None:
        await self.db.execute(
            """INSERT INTO bonds
               (bond_id, agent_a, agent_b, permissions, established_at,
                expires_at, renewal, revoked, revoked_by, revoked_at,
                signature_a, signature_b)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(bond_id) DO UPDATE SET
                 permissions=excluded.permissions,
                 revoked=excluded.revoked,
                 revoked_by=excluded.revoked_by,
                 revoked_at=excluded.revoked_at
            """,
            (
                bond["bond_id"],
                bond["agents"][0],
                bond["agents"][1],
                json.dumps(bond["permissions"]),
                bond["established_at"],
                bond["expires_at"],
                bond.get("renewal", "manual"),
                1 if bond.get("revoked") else 0,
                bond.get("revoked_by"),
                bond.get("revoked_at"),
                bond.get("signatures", {}).get(bond["agents"][0], ""),
                bond.get("signatures", {}).get(bond["agents"][1], ""),
            ),
        )
        await self.db.commit()

    async def get_bonds_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        cursor = await self.db.execute(
            """SELECT * FROM bonds
               WHERE (agent_a = ? OR agent_b = ?) AND revoked = 0""",
            (agent_id, agent_id),
        )
        rows = await cursor.fetchall()
        return [
            {
                "bond_id": r["bond_id"],
                "agents": [r["agent_a"], r["agent_b"]],
                "permissions": json.loads(r["permissions"]),
                "established_at": r["established_at"],
                "expires_at": r["expires_at"],
                "renewal": r["renewal"],
                "revoked": bool(r["revoked"]),
            }
            for r in rows
        ]

    async def get_bond(self, bond_id: str) -> dict[str, Any] | None:
        cursor = await self.db.execute(
            "SELECT * FROM bonds WHERE bond_id = ?", (bond_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "bond_id": row["bond_id"],
            "agents": [row["agent_a"], row["agent_b"]],
            "permissions": json.loads(row["permissions"]),
            "established_at": row["established_at"],
            "expires_at": row["expires_at"],
            "renewal": row["renewal"],
            "revoked": bool(row["revoked"]),
            "revoked_by": row["revoked_by"],
        }

    async def revoke_bond(self, bond_id: str, revoked_by: str, revoked_at: str) -> bool:
        cursor = await self.db.execute(
            """UPDATE bonds SET revoked=1, revoked_by=?, revoked_at=?
               WHERE bond_id=? AND revoked=0""",
            (revoked_by, revoked_at, bond_id),
        )
        await self.db.commit()
        return cursor.rowcount > 0

    # ---- Vouches ----

    async def insert_vouch(self, vouch: dict[str, Any]) -> int:
        cursor = await self.db.execute(
            """INSERT INTO vouches (attester, subject, domains, issued_at, expires_at, signature)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                vouch["attester"],
                vouch["subject"],
                json.dumps(vouch["domains"]),
                vouch["issued_at"],
                vouch["expires_at"],
                vouch.get("signature", ""),
            ),
        )
        await self.db.commit()
        return cursor.lastrowid

    async def get_vouches_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        cursor = await self.db.execute(
            "SELECT * FROM vouches WHERE subject = ? AND revoked = 0",
            (agent_id,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "attester": r["attester"],
                "subject": r["subject"],
                "domains": json.loads(r["domains"]),
                "issued_at": r["issued_at"],
                "expires_at": r["expires_at"],
            }
            for r in rows
        ]

    async def count_valid_vouches(self, agent_id: str, current_time: str) -> int:
        cursor = await self.db.execute(
            """SELECT COUNT(*) FROM vouches
               WHERE subject = ? AND revoked = 0 AND expires_at > ?""",
            (agent_id, current_time),
        )
        return (await cursor.fetchone())[0]

    # ---- Tasks ----

    async def insert_task(self, task: dict[str, Any]) -> None:
        await self.db.execute(
            """INSERT INTO tasks
               (task_id, requester, receiver, task_type, description,
                input_data, constraints, status, created_at, timeout_seconds)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task["task_id"],
                task["requester"],
                task["receiver"],
                task["task_type"],
                task.get("description", ""),
                json.dumps(task.get("input", {})),
                json.dumps(task.get("constraints", {})),
                "pending",
                task["created_at"],
                task.get("constraints", {}).get("max_duration_seconds", 300),
            ),
        )
        await self.db.commit()

    async def update_task_status(
        self, task_id: str, status: str, result: dict | None = None,
        error: dict | None = None, execution_metadata: dict | None = None,
    ) -> bool:
        fields = ["status = ?"]
        params: list[Any] = [status]

        if result:
            fields.append("result = ?")
            params.append(json.dumps(result))
        if error:
            fields.append("error = ?")
            params.append(json.dumps(error))
        if execution_metadata:
            fields.append("execution_metadata = ?")
            params.append(json.dumps(execution_metadata))

        if status == "completed" or status == "failed":
            fields.append("completed_at = datetime('now')")
        elif status == "accepted":
            fields.append("accepted_at = datetime('now')")

        params.append(task_id)
        cursor = await self.db.execute(
            f"UPDATE tasks SET {', '.join(fields)} WHERE task_id = ?",
            params,
        )
        await self.db.commit()
        return cursor.rowcount > 0

    async def get_task(self, task_id: str) -> dict[str, Any] | None:
        cursor = await self.db.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "task_id": row["task_id"],
            "requester": row["requester"],
            "receiver": row["receiver"],
            "task_type": row["task_type"],
            "description": row["description"],
            "status": row["status"],
            "result": json.loads(row["result"]) if row["result"] else None,
            "error": json.loads(row["error"]) if row["error"] else None,
            "created_at": row["created_at"],
            "completed_at": row["completed_at"],
            "execution_metadata": json.loads(row["execution_metadata"]) if row["execution_metadata"] else None,
        }

    async def get_active_tasks_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        cursor = await self.db.execute(
            """SELECT * FROM tasks
               WHERE receiver = ? AND status IN ('pending', 'accepted', 'in_progress')""",
            (agent_id,),
        )
        rows = await cursor.fetchall()
        return [{"task_id": r["task_id"], "status": r["status"], "task_type": r["task_type"]} for r in rows]

    # ---- Consensus ----

    async def insert_consensus_round(self, round_data: dict[str, Any]) -> None:
        await self.db.execute(
            """INSERT INTO consensus_rounds
               (consensus_id, initiator, topic, options, quorum_config,
                eligible_agents, deadline, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                round_data["consensus_id"],
                round_data["initiator"],
                round_data["topic"],
                json.dumps(round_data["options"]),
                json.dumps(round_data["quorum"]),
                json.dumps(round_data.get("eligible_agents")),
                round_data.get("deadline"),
                "open",
                round_data["created_at"],
            ),
        )
        await self.db.commit()

    async def insert_consensus_vote(self, vote: dict[str, Any]) -> bool:
        try:
            await self.db.execute(
                """INSERT INTO consensus_votes
                   (consensus_id, voter_id, vote, confidence, trust_score,
                    rationale_hash, signature, voted_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    vote["consensus_id"],
                    vote["voter_id"],
                    vote["vote"],
                    vote["confidence"],
                    vote["trust_score"],
                    vote.get("rationale_hash"),
                    vote.get("signature"),
                    vote["voted_at"],
                ),
            )
            await self.db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False  # Duplicate vote

    async def get_consensus_votes(self, consensus_id: str) -> list[dict[str, Any]]:
        cursor = await self.db.execute(
            "SELECT * FROM consensus_votes WHERE consensus_id = ?",
            (consensus_id,),
        )
        rows = await cursor.fetchall()
        return [
            {
                "voter_id": r["voter_id"],
                "vote": r["vote"],
                "confidence": r["confidence"],
                "trust_score": r["trust_score"],
            }
            for r in rows
        ]

    async def resolve_consensus(self, consensus_id: str, result: dict[str, Any]) -> None:
        await self.db.execute(
            "UPDATE consensus_rounds SET status='resolved', result=? WHERE consensus_id=?",
            (json.dumps(result), consensus_id),
        )
        await self.db.commit()

    async def get_consensus_round(self, consensus_id: str) -> dict[str, Any] | None:
        cursor = await self.db.execute(
            "SELECT * FROM consensus_rounds WHERE consensus_id = ?",
            (consensus_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "consensus_id": row["consensus_id"],
            "initiator": row["initiator"],
            "topic": row["topic"],
            "options": json.loads(row["options"]),
            "quorum": json.loads(row["quorum_config"]),
            "deadline": row["deadline"],
            "status": row["status"],
            "result": json.loads(row["result"]) if row["result"] else None,
        }

    # ---- Recovery Shares ----

    async def store_recovery_share(self, share: dict[str, Any]) -> None:
        await self.db.execute(
            """INSERT INTO recovery_shares
               (share_id, agent_id, scheme, threshold, total_shares,
                share_index, encrypted_share, key_fingerprint,
                custodian_key_id, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(agent_id, share_index) DO UPDATE SET
                 encrypted_share=excluded.encrypted_share,
                 key_fingerprint=excluded.key_fingerprint,
                 expires_at=excluded.expires_at
            """,
            (
                share["share_id"],
                share["agent_id"],
                share.get("scheme", "shamir-sss-gf256"),
                share["threshold"],
                share["total_shares"],
                share["share_index"],
                share["encrypted_share"],
                share["key_fingerprint"],
                share.get("custodian_key_id"),
                share["created_at"],
                share.get("expires_at"),
            ),
        )
        await self.db.commit()

    async def get_recovery_share(self, agent_id: str, share_index: int) -> dict[str, Any] | None:
        cursor = await self.db.execute(
            "SELECT * FROM recovery_shares WHERE agent_id = ? AND share_index = ?",
            (agent_id, share_index),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "share_id": row["share_id"],
            "agent_id": row["agent_id"],
            "share_index": row["share_index"],
            "encrypted_share": row["encrypted_share"],
            "key_fingerprint": row["key_fingerprint"],
            "threshold": row["threshold"],
            "total_shares": row["total_shares"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
        }

    async def delete_recovery_shares(self, agent_id: str) -> int:
        cursor = await self.db.execute(
            "DELETE FROM recovery_shares WHERE agent_id = ?", (agent_id,)
        )
        await self.db.commit()
        return cursor.rowcount

    async def cleanup_expired_shares(self, current_time: str) -> int:
        cursor = await self.db.execute(
            "DELETE FROM recovery_shares WHERE expires_at IS NOT NULL AND expires_at < ?",
            (current_time,),
        )
        await self.db.commit()
        return cursor.rowcount

    # ---- Knowledge Log ----

    async def log_knowledge_exchange(self, entry: dict[str, Any]) -> None:
        await self.db.execute(
            """INSERT INTO knowledge_log
               (knowledge_type, knowledge_id, sender, receiver, topic,
                confidence, pvl_passed, pvl_code, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry["knowledge_type"],
                entry["knowledge_id"],
                entry["sender"],
                entry["receiver"],
                entry.get("topic"),
                entry.get("confidence"),
                1 if entry["pvl_passed"] else 0,
                entry.get("pvl_code"),
                entry["timestamp"],
            ),
        )
        await self.db.commit()

    # ---- Message Deduplication ----

    async def check_and_record_message(self, message_id: str, received_at: str, expires_at: str) -> bool:
        """Returns True if message is new, False if duplicate."""
        try:
            await self.db.execute(
                "INSERT INTO message_ids (message_id, received_at, expires_at) VALUES (?, ?, ?)",
                (message_id, received_at, expires_at),
            )
            await self.db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    async def cleanup_expired_messages(self, current_time: str) -> int:
        cursor = await self.db.execute(
            "DELETE FROM message_ids WHERE expires_at < ?", (current_time,)
        )
        await self.db.commit()
        return cursor.rowcount

    # ---- Interactions ----

    async def log_interaction(
        self, from_agent: str, to_agent: str,
        interaction_type: str, rating: float | None, timestamp: str,
    ) -> None:
        await self.db.execute(
            """INSERT INTO interactions (from_agent, to_agent, interaction_type, rating, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (from_agent, to_agent, interaction_type, rating, timestamp),
        )
        await self.db.commit()

    async def get_reputation(self, agent_id: str, days: int = 90) -> float:
        cursor = await self.db.execute(
            """SELECT AVG(rating) FROM interactions
               WHERE to_agent = ? AND rating IS NOT NULL
               AND timestamp > datetime('now', ?)""",
            (agent_id, f"-{days} days"),
        )
        row = await cursor.fetchone()
        return row[0] if row[0] is not None else 0.5
