\# OCP Python SDK



Reference Python SDK for the \*\*OpenCognition Protocol (OCP)\*\* — an open,

decentralized standard for AI-to-AI communication.



\## Installation



```bash

pip install ocp-protocol

```



For development:



```bash

pip install ocp-protocol\[dev]

```



\## Quick Start



```python

import asyncio

from ocp import Agent



async def main():

&#x20;   agent = Agent(

&#x20;       name="MyResearchAI",

&#x20;       capabilities=\["nlp:classification", "nlp:summarization"],

&#x20;       domains=\["research"],

&#x20;   )

&#x20;   await agent.register()

&#x20;   peers = await agent.discover(domain="research")

&#x20;   print(f"Found {len(peers)} peers")

&#x20;   await agent.close()



asyncio.run(main())

```



\## Documentation



Full documentation: https://opencognitionprotocol.org/docs/sdk/python



\## License



MIT



