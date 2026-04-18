"""Example: Create a simple OCP agent, register, discover peers, and exchange a message.

This is the minimal "hello world" for OCP. It demonstrates:
  1. Agent creation (identity generation, capability declaration)
  2. Network registration
  3. Peer discovery by domain and capability
  4. Sending a direct message

Usage:
    python examples/simple_agent.py
"""

import asyncio
from ocp import Agent, MessageType


async def main() -> None:
    # ---- Step 1: Create an agent ----
    agent = Agent(
        name="SimpleResearchAI",
        capabilities=["nlp:classification", "nlp:summarization"],
        domains=["research", "literature_review"],
        service_endpoint="wss://my-ai.example.com/ocp/v1/ws",
    )

    print(f"Agent created")
    print(f"  Name:        {agent.name}")
    print(f"  Agent ID:    {agent.agent_id}")
    print(f"  Network:     {agent.identity.network}")
    print(f"  Fingerprint: {agent.identity.key_fingerprint}")
    print(f"  Trust level: {agent.trust_level.name}")
    print()

    # ---- Step 2: Register on the network ----
    try:
        result = await agent.register()
        print(f"Registered on network: {result}")
    except Exception as e:
        print(f"Registration failed (expected without a running registry): {e}")
    print()

    # ---- Step 3: Discover peers ----
    try:
        peers = await agent.discover(
            domain="research",
            capability="nlp:classification",
            min_trust_level=0,
            limit=10,
        )
        print(f"Discovered {len(peers)} peers:")
        for p in peers:
            print(f"  - {p.get('display_name', 'unknown')} ({p.get('agent_id', 'unknown')})")
            print(f"    Domains: {p.get('domains', [])}")
            print(f"    Trust:   Level {p.get('trust_level', 0)}")
    except Exception as e:
        print(f"Discovery failed (expected without a running registry): {e}")
    print()

    # ---- Step 4: Build a message (without sending) ----
    from ocp.messages import MessageBuilder, Priority

    peer_id = "did:ocp:mainnet:agent-aabbccddeeff"  # placeholder
    msg = (
        MessageBuilder(agent.agent_id, agent.identity.signing_keys)
        .to(peer_id)
        .type(MessageType.DISCOVERY_PING)
        .payload({
            "capabilities": ["cap:nlp:classification", "cap:nlp:summarization"],
            "domains": ["research"],
            "trust_level": agent.trust_level.value,
        })
        .tag("research")
        .priority(Priority.NORMAL)
        .ttl(3600)
        .build()
    )
    print(f"Message built:")
    print(f"  ID:     {msg['message_id']}")
    print(f"  Type:   {msg['message_type']}")
    print(f"  Sender: {msg['sender']['agent_id']}")
    print(f"  Signed: {msg['sender']['signature'][:32]}...")
    print()

    # ---- Step 5: Verify the message we just built ----
    from ocp.messages import MessageValidator

    validator = MessageValidator()
    try:
        validator.validate(msg, agent.identity.signing_keys.public_key_bytes)
        print("Message signature verified successfully")
    except Exception as e:
        print(f"Verification failed: {e}")

    # ---- Cleanup ----
    await agent.close()
    print("\nAgent closed. Done.")


if __name__ == "__main__":
    asyncio.run(main())
