# =============================================================================
# Metasploit MCP Server Dockerfile
# =============================================================================

FROM metasploitframework/metasploit-framework:latest

# -----------------------------------------------------------------------------
# Install Dependencies
# -----------------------------------------------------------------------------
RUN apk update && \
    apk add --no-cache \
    python3 \
    py3-pip \
    git \
    curl \
    bash \
    postgresql-client \
    netcat-openbsd \
    net-tools \
    && rm -rf /var/cache/apk/*

# -----------------------------------------------------------------------------
# Clone MetasploitMCP Repository
# -----------------------------------------------------------------------------
WORKDIR /app

RUN git clone https://github.com/GH05TCREW/MetasploitMCP.git /app/MetasploitMCP

# -----------------------------------------------------------------------------
# Install Python Dependencies
# -----------------------------------------------------------------------------
WORKDIR /app/MetasploitMCP

RUN pip3 install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Copy Startup Script
# -----------------------------------------------------------------------------
COPY scripts/docker/start_msf_mcp.sh /app/start_msf_mcp.sh
RUN chmod +x /app/start_msf_mcp.sh

# -----------------------------------------------------------------------------
# Expose Ports
# -----------------------------------------------------------------------------
EXPOSE 55553 8085

# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------
# Check if port 8085 is listening
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=3 \
    CMD nc -z localhost ${MCP_HTTP_PORT} || exit 1

# -----------------------------------------------------------------------------
# Run Startup Script
# -----------------------------------------------------------------------------
CMD ["/app/start_msf_mcp.sh"]