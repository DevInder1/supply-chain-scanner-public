# Dockerfile for tridentchain-mcp — stdio MCP server for TridentChain Security.
# Used by Glama (https://glama.ai) for automated server-listing verification and by
# any host that wants a containerised MCP runtime.
#
# What the container does at runtime:
#   - Runs `python -m tridentchain_mcp` as PID 1
#   - Communicates over stdin/stdout with MCP JSON-RPC frames
#   - Responds to `initialize` and `tools/list` (Glama's introspection checks)
#   - Exposes three tools: scan_project, scan_full, validate_after_patch
#
# Build:  docker build -t tridentchain-mcp .
# Run:    docker run --rm -i tridentchain-mcp        (stdio; -i is required)

FROM python:3.12-slim

# Metadata used by Glama and other registries.
LABEL org.opencontainers.image.title="tridentchain-mcp"
LABEL org.opencontainers.image.description="Local supply-chain CVE scanner MCP server (OSV, NVD, EPSS, KEV)"
LABEL org.opencontainers.image.source="https://github.com/DevInder1/supply-chain-scanner-public"
LABEL org.opencontainers.image.licenses="MIT"
LABEL io.modelcontextprotocol.server.name="io.github.DevInder1/tridentchain-security"

# System deps: git is occasionally needed for git-based dep resolution; ca-certs
# lets the scanner query OSV/NVD over HTTPS. Everything else stays out of the image
# to keep the surface area small.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Non-root user — no reason for the scanner to run as root inside a container.
RUN useradd --create-home --shell /bin/bash --uid 1000 tridentchain
WORKDIR /home/tridentchain

# Install from PyPI. Pinning to explicit versions makes the image reproducible and
# lets Glama's automated check hit a known-good build.
RUN pip install --no-cache-dir \
      "tridentchain-security==0.1.4" \
      "tridentchain-mcp==0.1.4"

USER tridentchain

# stdio transport: run as PID 1 so signals reach the Python process and
# so that stdin/stdout are the MCP transport channel.
ENTRYPOINT ["python", "-m", "tridentchain_mcp"]
