# 🕸️OpenCognition Protocol (OCP)

**A decentralized open standard for collective AI intelligence.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OCP Version](https://img.shields.io/badge/OCP-v1.0-green.svg)](spec/SPECIFICATION.md)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

OCP is an open, decentralized, privacy-preserving communication protocol that enables AI systems to discover one another, exchange knowledge, delegate tasks, and form collaborative relationships across organizational and platform boundaries.

## 🗂️Repository Structure

```
ocp-protocol/
├── spec/                        # Protocol specification (PDFs)
│   ├── CHANGELOG.md             # Spec version history & migration guides
│   ├── protocol/                # Technical Spec Documents
│   │   ├── ocp-technical-spec-v1.pdf
│   └── setup/                   # Implementation & Node guides
│       └── ocp-setup-guide.pdf
├── schemas/                     # JSON Schemas definitions
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
├── sdk/                         # Software Development Kit
│   └── python/                  # Python SDK
│       ├── pyproject.toml
│       └── ocp/
│           ├── __init__.py
│           ├── agent.py         # Agent class
│           ├── cli.py         	 # Command-line utility
│           ├── compliance.py    # Compliance checker
│           ├── consensus.py     # Consensus protocol
│           ├── constants.py     # Protocol-level constants
│           ├── crypto.py        # Cryptographic primitives
│           ├── exceptions.py    # Error type hierarchy
│           ├── identity.py      # DID generation & resolution
│           ├── knowledge.py     # Knowledge types
│           ├── messages.py      # OCPUMF builder & validator
│           ├── pvl.py           # Privacy Validation Layer
│           ├── recovery.py      # Key recovery
│           ├── registry.py      # Agent registry client
│           ├── transport.py     # Transport layer (WS + HTTP)
│           └── trust.py         # Trust & bonding
├── node/                        # Reference OCP Node Implementation
│   ├── Dockerfile               # Container build specification
│   ├── docker-compose.yml       # Multi-container orchestration
│   ├── config.yml               # Global protocol settings
│   └── src/
│       └── ocp_node/            # Core Node Service
│           ├── __init__.py
│           ├── __main__.py      # Execution entry point
│           ├── custodian.py     # State & Key management
│           ├── database.py      # Persistence layer
│           ├── handlers.py      # Request logic
│           ├── router.py        # Message routing logic
│           ├── registry.py      # Local registry service
│           └── transport.py     # Network server (WS/HTTP)
├── tests/                       # Compliance Test Suite
│   ├── conftest.py              # Global test configuration and fixtures
│   ├── test_crypto.py           # Cryptographic & signature verification
│   ├── test_identity.py         # Validating Agent identities
│   ├── test_messages.py         # Message format & parsing
│   ├── test_transport.py        # Secure transport & network tests
│   ├── test_pvl.py              # PVL engine & logic validation
│   ├── test_recovery.py         # Protocol recovery & resilience
│   ├── test_knowledge.py        # Knowledge query & state tests
│   ├── test_trust.pyn           # Trust model & scoring tests
│   └── test_consensus.py        # Multi-agent consensus & sync
├── examples/                    # Example agents
│   ├── simple_agent.py
│   ├── knowledge_sharing.py
│   └── multi_agent_consensus.py
├── .gitignore                   # Master ignore file
├── LICENSE                      # MIT License
├── CONTRIBUTING.md              # How to contribute
├── CODE_OF_CONDUCT.md           # Community standards
├── SECURITY.md                  # Security and resilance standards
├── GOVERNANCE.md                # Community-led decision model
└── README.md                    # Project Overview

## Quick Start

### Install the Python SDK

```bash
pip install ocp-protocol
```

### Create and register an agent

```python
from ocp import Agent

agent = Agent(
    name="MyResearchAI",
    capabilities=["nlp:classification", "nlp:summarization"],
    domains=["research"],
)

await agent.register()
peers = await agent.discover(domain="research", capability="nlp:classification")
print(f"Found {len(peers)} peers")
```

### 🚀Run a local OCP node

```bash
cd node/
docker compose up -d
```

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
pytest tests/ -v --cov=ocp --cov-fail-under=85

```

## 🤝Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🔒Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).

## 🏛️ Governance
Our decision-making process is outlined in [GOVERNANCE.md](GOVERNANCE.md).

## 📜License

MIT — see [LICENSE](LICENSE).

