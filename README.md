# 🕸️OpenCognition Protocol (OCP)

**A decentralized open standard for collective AI intelligence.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OCP Version](https://img.shields.io/badge/OCP-v1.0-green.svg)](spec/SPECIFICATION.md)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

OCP is an open, decentralized, privacy-preserving communication protocol that enables AI systems to discover one another, exchange knowledge, delegate tasks, and form collaborative relationships across organizational and platform boundaries.

## 🗂️Repository Structure

```
ocp-protocol/
├──📘spec/                       # Protocol specification (PDFs)
│   ├── CHANGELOG.md             # Spec version history & migration guides
│   ├── protocol/                # Technical Spec Documents
│   │   ├── ocp-technical-spec-v1.pdf
│   └── setup/                   # Implementation & Node guides
│   │   └── ocp-setup-guide.pdf
│   └── ethics/                  # Integration Manuals
│   │   ├── ocp-ethics-framework-complete-guide-v2.1.pdf
│   │   ├── ocp-ethics-integration-specification-v2.1.pdf
│   └── └── ocp-ethics-setup-and-installation-guide.pdf
├── 📐schemas/                   # JSON Schemas definitions
│   ├── ocpumf.schema.json       # Universal Message Format
│   ├── agent-record.schema.json # Agent Registry record
│   ├── did-document.schema.json # OCP DID Document
│   ├── bond-record.schema.json  # Bond record
│   ├── vouch-record.schema.json # Signed endorsement between agents
│   ├── consensus/               # Multi-agent agreement protocols
│   │   ├── consensus-initiate.json
│   │   ├── consensus-result.json
│   │   └── consensus-vote.json
│   ├── discovery/               # Peer & Capability finding
│   │   ├── capability-query.json
│   │   ├── capability-response.json
│   │   └── discovery-ping.json
│   ├── errors/                  # Standardized error reporting
│   │   └── error-response.json
│   ├── ethics/                  # Ethics Schema Validation Engine
│   │   ├── consent-token.schema.json            
│   │   ├── eal-entry.schema.json 
│   │   ├── ethics-metadata.schema   
│   │   ├── pur-entry.schema.json                        
│   │   └── transparency-card.schema.json                    
│   ├── knowledge/               # Data, Embeddings, and Model updates
│   │   ├── embedding.json
│   │   ├── insight.json
│   │   └── model-delta.json
│   ├── recovery/                # Secret sharing & state recovery
│   │   ├── recovery-request.json
│   │   ├── recovery-share.json
│   │   └── recovery-share-response.json
│   ├── registry/                # Global/Local Agent Directory lookups
│   │   ├── discover-request.json
│   │   └── discover-response.json
│   ├── tasks/                   # Action & Workflow execution
│   │   ├── task-request.json
│   │   └── task-response.json
│   └── transport/               # Secure handshake & auth layer
│       ├── auth-handshake.json
│       └── auth-result.json
├── 📦sdk/                       # Software Development Kit
│   └── python/                  # Python SDK
│       ├── pyproject.toml
│       └── ocp/
│           ├── __init__.py
│           ├── agent.py         # Agent class
│           ├── cli.py         	 # Command-line utility
│           ├── compliance.py    # Protocol conformance checker
│           ├── consensus.py     # Consensus protocol
│           ├── constants.py     # Protocol-level constants
│           ├── crypto.py        # Cryptographic primitives
│           ├── exceptions.py    # Error type hierarchy
│           ├── identity.py      # DID generation & resolution
│           ├── knowledge.py     # Knowledge types
│           ├── messages.py      # OCPUMF builder & validator
│           ├── pvl.py           # Privacy Validation Layer (PII Scrubbing)
│           ├── recovery.py      # Key recovery
│           ├── registry.py      # Agent registry client
│           ├── transport.py     # Transport layer (WS + HTTP)
│           └── trust.py         # Trust & bonding
│           └── ⚖️ ethics/       # Ethics Enforcement Engine Submodule
│               ├── __init__.py
│               ├── agent_record_ext.py
│               ├── bias.py
│               ├── bond_ethics.py
│               ├── cascade.py
│               ├── cognitive.py
│               ├── compliance_checker.py
│               ├── compute_footprint.py
│               ├── consensus_integrity.py
│               ├── consent.py
│               ├── constants.py
│               ├── data_sovereignty.py
│               ├── decommission.py
│               ├── did_ext.py
│               ├── dual_use.py
│               ├── eal.py
│               ├── emergent_behavior.py
│               ├── evl.py
│               ├── exceptions.py
│               ├── knowledge_expiry.py
│               ├── message_ethics.py
│               ├── model_collapse.py
│               ├── notifications.py
│               ├── power_dynamics.py
│               ├── pur.py
│               ├── risk_classification.py
│               ├── sanctions.py
│               ├── synthetic.py
│               ├── training_provenance.py
│               ├── transparency.py
│               └── trust_anti_gaming.py
├── 🏗️node/                      # Reference OCP Node Implementation
│   ├── Dockerfile               # Container build specification
│   ├── docker-compose.yml       # Multi-container orchestration
│   ├── config.yml               # Global protocol settings
│   └── src/
│       └── ocp_node/            # Core Node Service
│           ├── __init__.py
│           ├── __main__.py      # Execution entry point
│           ├── custodian.py     # Secret management & State persistence
│           ├── database.py      # Persistence layer
│           ├── handlers.py      # Request logic
│           ├── router.py        # Message routing logic
│           ├── registry.py      # Local registry service
│           └── transport.py     # Network server (WS/HTTP)
├── ✅tests/                     # Compliance Test Suite
│   ├── conftest.py              # Global test configuration and fixtures
│   ├── test_crypto.py           # Cryptographic & signature verification
│   ├── test_identity.py         # Validating Agent identities
│   ├── test_messages.py         # Message format & parsing
│   ├── test_transport.py        # Secure transport & network tests
│   ├── test_pvl.py              # PVL engine & logic validation
│   ├── test_recovery.py         # Protocol recovery & resilience
│   ├── test_knowledge.py        # Knowledge query & state tests
│   ├── test_trust.py            # Trust model & scoring tests
│   ├── test_consensus.py        # Multi-agent consensus & sync
│   ├── test_evl.py              # Async EVL pipeline tests
│   ├── test_subsystems.py       # Async Subsystem validations
│   └── test_v20_modules.py      # Core modular compliance checkpoints
├── examples/                    # Example agents
│   ├── start_agent.py           # HelloWorldAgent 👋
│   ├── research_demo.py         # Targeted discovery with error handling 🧪
│   ├── client_test.py           # End-to-end test: Discovery, Delegation, and Vouching 🔄
│   ├── simple_agent.py          # Identity generation and network discovery
│   ├── key_recovery.py          # 3-of-5 Shamir recovery and key rotation
│   ├── knowledge_sharing.py     # PII scrubbing (PVL) and secure data exchange
│   └── multi_agent_consensus.py # Weighted voting and collective decision making
├── .gitignore                   # Master ignore file
├── LICENSE                      # MIT License
├── CONTRIBUTING.md              # How to contribute
├── CODE_OF_CONDUCT.md           # Community standards
├── SECURITY.md                  # Security and resilance standards
├── GOVERNANCE.md                # Community-led decision model
└── README.md                    # Project Overview
```
### 🚀 Quick Start
Get your first OCP agent up and running in less than 5 minutes.

Installation
The OCP SDK requires Python 3.11+ and a specific stack for cryptography and high-performance networking. We recommend using a virtual environment.

📥Clone the Repository
```bash
# Using SSH
git clone git@github.com:opencognitionprotocol/ocp-protocol.git

# Using HTTPS
git clone https://github.com/opencognitionprotocol/ocp-spec.git
````
⚙️Install the SDK

```bash
# Install in editable mode with all dependencies
cd ocp-protocol/sdk/python
pip install -e .
```
🔍Verify Installation

Confirm the CLI tools are available in your path:
```bash
ocp-keygen --help
```
🔑Generate Identity

Every OCP agent requires a unique cryptographic identity to interact with the network. This process generates an Ed25519 keypair (for signing messages) and an X25519 keypair (for encryption).

```bash
# Run the following command to initialize your identity:
ocp-keygen --output identity.json
```
📦 What's inside identity.json?

The generated file acts as your agent's "passport" and contains:

* **Agent ID:** Your unique Decentralized Identifier (did:ocp:...).

* **Signing Keys:** Proof of authorship for every message you send.

* **Encryption Keys:** Used to establish secure, private channels with other agents.

[!WARNING]
**Keep your private keys private.** The identity.json file contains sensitive secrets. Never commit this file to version control. Our SDK is pre-configured with a .gitignore to help keep your identity safe.
### Run a Local OCP Node
OCP agents require a Registry to find peers and a Transport node to route messages. Start these in two separate terminal windows:
* **Terminal 1** (Registry): python -m ocp_node.registry
* **Terminal 2** (Transport): python -m ocp_node.transport
### 📡Create and register an agent
Initialize your agent(e.g., my_agent.py) and announce its capabilities to the network.
```python
import asyncio
from ocp.agent import Agent

async def main():
    # Initialize the Agent with specific capabilities
    agent = Agent(
        name="ResearchWorker",
        capabilities=["nlp:summary"],
        domains=["research"],
        registry_url="http://127.0.0.1:8422/ocp/v1"
    )

    # Register with the local Registry
    await agent.register()
    print(f"✅ Agent {agent.name} is LIVE!")
    print(f"🆔 DID: {agent.agent_id}")

    # Listen for tasks indefinitely
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await agent.close()

if __name__ == "__main__":
    asyncio.run(main())
```

### 🛠️ Operational Commands
Use these commands to verify the health and monitor the activity of your local OCP network once servers are live:

| Action | Command |
| :--- | :--- |
| **Check Registry Health** | `curl http://127.0.0.1:8422/health` |
| **Check Transport Health** | `curl http://127.0.0.1:8420/health` |
| **View Network Stats** | `curl http://127.0.0.1:8422/ocp/v1/registry/stats` |
| **List Active Agents** | `curl -X POST http://127.0.0.1:8422/ocp/v1/registry/discover -d "{}"` |
| **View Task Summary** | `curl http://127.0.0.1:8420/ocp/v1/tasks/summary` |

## 📖 Specification

This section outlines the theoretical, ethical, and technical foundations of the Open Cognition Protocol.


### Core Specifications
These foundational documents are maintained on the [Official OCP Website](https://www.opencognitionprotocol.org/get-started/) to ensure you are always accessing the latest versions.

* **White Paper (v1.0):** [Download ↗](https://www.opencognitionprotocol.org/_files/ugd/1933f6_d3d41eedf76e411196ea72c7f9d2d8e1.pdf) — The foundational vision and protocol architecture.
* **Academic White Paper:** [View ↗](https://www.opencognitionprotocol.org/_files/ugd/1933f6_75e47514b2624d0cba2576c80778e123.pdf) — Formal theoretical framework and cognitive models.
* **Ethics & Regulatory Documentation:** [Read ↗](https://www.opencognitionprotocol.org/_files/ugd/1933f6_c59db361e97343c99fd707e1b819a040.pdf) — Compliance standards and AI safety principles.
* **Blockchain Innovation Extension:** [Explore ↗](https://www.opencognitionprotocol.org/_files/ugd/1933f6_e7d010dc681043ed9b4bfda09b2b340c.pdf) — Decentralized ledger and incentive layers.

### Implementation Specs
Technical documentation for developers implementing or auditing the OCP node.

* **Technical Specification:** The full technical details can be found in the [OCP Technical Specification (PDF)](spec/protocol/ocp-technical-spec-v1.pdf).
* **Test Cases:** Detailed test scenarios are documented in the [OCP Test Case Specification (PDF)](spec/protocol/ocp-test-case-spec-v1.pdf).

---

## 🧪 Testing

The OCP Compliance Test Suite ensures full adherence to the protocol specification.

* **Test Directory:** `tests/`
* **Test Count:** 70 test cases across 10 categories.
* **Requirements:** `pytest`, `pytest-cov`

### Running the Suite
To run the full suite with coverage reporting:

```bash
pytest tests/ -v --cov=ocp --cov-fail-under=90
```

## 🤝Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🔒Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).

## 🏛️ Governance
Our decision-making process is outlined in [GOVERNANCE.md](GOVERNANCE.md).

## 📜License

MIT — see [LICENSE](LICENSE).

