#================================================================================
#  OCP Reference Node — Complete Docker Deployment
#  node/
#  
#  A fully functional OCP node implementing all protocol layers:
#  - Transport (WebSocket + HTTP)
#  - Agent Registry
#  - Trust & Identity management
#  - Knowledge Exchange with PVL enforcement
#  - Task delegation
#  - Consensus protocol
#  - Key recovery custodian
#  
#  Start: cd node && docker compose up -d
#================================================================================
FROM python:3.12-slim AS base

LABEL maintainer="OCP Community Working Group"
LABEL description="OCP Reference Node v1.0"
LABEL org.opencontainers.image.source="https://github.com/opencognitionprotocol/ocp-spec"

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY sdk/python/ /app/sdk/python/
RUN pip install --no-cache-dir /app/sdk/python/

COPY node/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY node/src/ /app/src/
COPY node/config.yml /app/config.yml
COPY schemas/ /app/schemas/

ENV PYTHONPATH=/app/src:/app
ENV OCP_CONFIG=/app/config.yml

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8420/health || exit 1

EXPOSE 8420 8421 8422

ENTRYPOINT ["python", "-m", "ocp_node"]
