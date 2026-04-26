"""OCP WORKER AGENT: RESEARCH AI (PROVIDER)

ROLE:
Acts as a service provider in the 'research' domain.
Registers its capabilities so Clients can find it via the Registry.

PREREQUISITES:
1. Registry Server must be running (Port 8422)
2. Transport Server must be running (Port 8420)

HOW TO RUN:
Prompt> python examples/research_demo.py

AUDITING THE WORKER (External HTTP Calls):
- Verify Registration: curl http://127.0.0.1:8422/ocp/v1/registry/agents/{AGENT_ID}
- Check Capabilities: curl http://127.0.0.1:8422/ocp/v1/registry/discover -X POST -d '{"filters": {"capabilities": ["cap:nlp:classification"]}}'
- Check Task Queue:   curl http://127.0.0.1:8420/ocp/v1/tasks/summary
"""

import asyncio
import logging

from ocp.agent import Agent

# Enable logging to see the 'Heartbeat' and 'Registration' logs
logging.basicConfig(level=logging.INFO)


async def main():
    # INITIALIZE THE PROVIDER
    # Agent defines 'capabilities' that others search for.
    agent = Agent(
        name="MyResearchAI",
        capabilities=["nlp:classification"], # This gets stored as 'cap:nlp:classification'
        domains=["research"],
        network="local",
        registry_url="http://127.0.0.1:8422/ocp/v1"
    )

    try:
        # IDENTITY RECOGNITION
        # agent_id is derived from its public key (DID)
        print(f"\n🆔 Agent ID: {agent.agent_id}")

        # NETWORK REGISTRATION (HTTP: POST /registry/agents)
        # Announces the agent to the network so it appears in discovery results.
        print("📡 Registering with OCP Registry...")
        await agent.register()
        print("✅ Registration Successful!")

        # MESSAGE LISTENING (The "Service" Phase)
        # In a full OCP implementation, the agent would connect to the
        # Transport server's WebSocket or Long-Polling endpoint.
        print("\n🚀 Agent is now LIVE and listening for tasks...")
        print("-------------------------------------------------")
        print("Status: AVAILABLE")
        print("Domain: research")
        print("Task Type: nlp:classification")
        print("-------------------------------------------------")

        # KEEP-ALIVE LOOP
        # Agents must stay running to respond to 'Pings' or 'Task Delegations'.
        # If process exits, the agent is considered 'Offline' by the network.
        print("Press Ctrl+C to stop this agent.")
        while True:
            # This is where the agent 'idles'.
            # In production, the SDK handles background task processing here.
            await asyncio.sleep(1)

    except asyncio.CancelledError:
        print("\n👋 Shutdown signal received.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        # Cleanup: In some OCP nodes, this may send a 'Deregister' signal
        await agent.close()
        print("🏁 Agent offline.")

if __name__ == "__main__":
    print("🧪 Research AI status: Initialized and ready.")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass # Handle Ctrl+C gracefully at the top level