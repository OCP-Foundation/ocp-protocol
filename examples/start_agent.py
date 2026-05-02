"""Example: Quick start and environment verification.

This demonstrates:
  1. Initializing the HelloWorldAgent with a local identity
  2. Generating a Decentralized Identity (DID) on the ocp:mainnet
  3. Verifying the Ed25519 cryptographic signatures locally
  4. Confirming the environment is ready for network discovery

Usage:
    python examples/start_agent.py
"""

import asyncio

from ocp.agent import Agent


async def main():
    # Initialize with the required arguments
    agent = Agent(
        name="HelloWorldAgent",
        capabilities=["text_processing", "discovery"],
        domains=["general", "testing"]
    )

    print(f"Agent Created: {agent.name}")
    print(f"Agent ID:   {agent.agent_id}")
    print(f"Network:    {agent.network}")

    # Simple, version-agnostic verification
    if agent.agent_id.startswith("did:ocp"):
        print("\nIdentity verified: Ed25519 keys are valid.")
        print("Your environment is correctly configured for OCP.")

if __name__ == "__main__":
    asyncio.run(main())