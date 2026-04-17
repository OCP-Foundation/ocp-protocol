# OpenCognition Protocol (OCP)

**A decentralized open standard for collective AI intelligence.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OCP Version](https://img.shields.io/badge/OCP-v1.0-green.svg)](spec/SPECIFICATION.md)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

OCP is an open, decentralized, privacy-preserving communication protocol that enables AI systems to discover one another, exchange knowledge, delegate tasks, and form collaborative relationships across organizational and platform boundaries.

## Repository Structure

```
ocp-protocol/
├── spec/                        # Protocol specification
│   ├── CHANGELOG.md             # Spec version history & migration guides
│   ├── protocol/                # Technical Spec Documents
│   │   ├── ocp-technical-spec-v1.pdf
│   │   └── ocp-whitepaper.pdf
│   └── setup/                   # Implementation & Node guides
│       └── ocp-setup-guide.pdf
├── schemas/                     # JSON Schemas
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
├── sdk/                         # Reference SDKs
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
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── config.yml
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
├── tests/                       # Compliance test suite
│   ├── conftest.py
│   ├── test_identity.py
│   ├── test_messages.py
│   ├── test_crypto.py
│   ├── test_knowledge.py
│   ├── test_trust.py
│   ├── test_transport.py
│   ├── test_pvl.py
│   └── test_consensus.py
├── examples/                    # Example agents
│   ├── simple_agent.py
│   ├── knowledge_sharing.py
│   └── multi_agent_consensus.py
├── .gitignore                   # Master ignore file
├── LICENSE                      # MIT License
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── GOVERNANCE.md
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

### Run a local OCP node

```bash
cd node/
docker compose up -d
```

## Specification

* **Technical Specification:** The full technical details can be found in the [OCP Technical Specification (PDF)](spec/protocol/ocp-technical-spec-v1.pdf).
* **Test Cases:** Detailed test scenarios are documented in the [OCP Test Case Specification (PDF)](spec/protocol/ocp-test-case-spec-v1.pdf).
 
## Testing

The OCP Compliance Test Suite ensures full adherence to the protocol specification.

* **Test Directory:** `tests/`
* **Test Count:** 70 test cases across 9 categories.
* **Requirements:** `pytest`, `pytest-cov`

### Running the Suite

To run the full suite with coverage reporting:

```bash```
pytest tests/ -v --cov=ocp --cov-fail-under=85

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).

