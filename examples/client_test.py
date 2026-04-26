"""OCP CLIENT TEST SUITE: REPUTATION & TASK DELEGATION

ROLE:
Service Requester (The "Employer" Agent)
Demonstrates the full Trust Loop—Discovery, Delegation, and Reputation.

PREREQUISITES:
1. Registry Server running: python -m ocp_node.registry (Port 8422)
2. Transport Server running: python -m ocp_node.transport (Port 8420)
3. Research Agent running: python examples/research_demo.py

HOW TO RUN:
Prompt> python examples/client_test.py

AUDITING THE NETWORK (External HTTP Calls):
- Check Network Health: curl http://127.0.0.1:8422/health
- Check Global Stats:   curl http://127.0.0.1:8422/ocp/v1/registry/stats
- View All Agents:      curl http://127.0.0.1:8422/ocp/v1/registry/discover -X POST -d "{}"
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from ocp.agent import Agent
from ocp.crypto import b64url_encode

# Configure logging to see the protocol handshakes
logging.basicConfig(level=logging.INFO)


async def main():
    # INITIALIZE IDENTITY
    # Generates a new Ed25519 keypair for this session
    client = Agent(
        name="TestClient",
        capabilities=["client:request"],
        domains=["testing"],
        network="local",
        registry_url="http://127.0.0.1:8422/ocp/v1"
    )

    try:
        # CONNECT TO TRANSPORT
        # Routes signed messages to other agents
        await client.connect_http(url="http://127.0.0.1:8420/ocp/v1/messages")

        # DISCOVERY (HTTP: POST /registry/discover)
        # Finds agents with specific NLP capabilities in the local network
        print("\n🔍 Searching for an NLP agent...")
        peers = await client.discover(capability="cap:nlp:classification")

        if not peers:
            print("❌ No NLP agents found. Ensure research_demo.py is active.")
            return

        target_id = peers[0]['agent_id']
        print(f"✅ Found agent: {target_id}")

        # TASK DELEGATION (HTTP: POST /messages)
        # Packages the task in an OCPUMF frame, signs it, and sends it
        print("✉️ Delegating task...")
        response = await client.delegate_task(
            to=target_id,
            task_type="nlp:classification",
            description="Autonomous quality check",
            input_data={"text": "The OCP protocol is revolutionary!"}
        )
        print(f"🎉 Task accepted! Response: {response}")

        # REPUTATION LOOP (HTTP: POST /registry/vouches)
        # If task is successful, submit a Vouch to Registry to increase agent reputation
        if response.get("status") == "ok":
            print(f"\n⭐ Vouching for agent {target_id}...")

            # Manually construct the payload to match RegistryServer expectations
            sig_data = f"vouch:{client.agent_id}:{target_id}".encode()
            manual_signature = client.identity.signing_keys.sign(sig_data)

            vouch_payload = {
                "attester": client.agent_id,
                "subject": target_id,
                "domains": ["research"],
                "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "signature": b64url_encode(manual_signature)
            }

            # Submit directly to the Vouch endpoint found in registry_server.py
            endpoint = f"{client.registry_url}/registry/vouches"
            resp = await client._registry._client.post(endpoint, json=vouch_payload)

            if resp.status_code == 201:
                print(f"🚀 Success! Vouch ID: {resp.json().get('vouch_id')}")
            else:
                print(f"⚠️ Registry rejected vouch: {resp.status_code}")

    except Exception as e:
        print(f"\n❌ Client Error: {e}")

    finally:
        # Gracefully shut down connections
        await client.close()
        print("\n🏁 Client session closed.")


if __name__ == "__main__":
    asyncio.run(main())