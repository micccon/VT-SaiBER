FROM kalilinux/kali-rolling:latest

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    # Core tools
    curl \
    python3 \
    python3-pip \
    # Security tools
    nmap \
    masscan \
    gobuster \
    ffuf \
    dirb \
    nikto \
    sqlmap \
    hydra \
    john \
    enum4linux \
    wpscan \
    # Networking utilities
    netcat-traditional \
    iputils-ping \
    dnsutils \
    whois \
    # Wordlists
    wordlists \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# 2. Add Kali MCP Server Source (local pinned copy)
# -----------------------------------------------------------------------------
WORKDIR /app

COPY third_party/MCP-Kali-Server /app/kali-mcp

WORKDIR /app/kali-mcp

# -----------------------------------------------------------------------------
# 3. Install Dependencies from Repo
# -----------------------------------------------------------------------------
RUN pip3 install --no-cache-dir --break-system-packages \
    -r requirements.txt

# Install uvicorn for SSE support
RUN pip3 install --no-cache-dir --break-system-packages uvicorn

# -----------------------------------------------------------------------------
# 4. Overwrite with Fixed MCP Server
# -----------------------------------------------------------------------------
# Copy our fixed mcp_server.py that supports --host and --port
COPY src/mcp/kali_mcp_server.py /app/kali-mcp/mcp_server.py

# Copy startup script
COPY scripts/docker/start_kali_mcp.sh /app/start_kali_mcp.sh

# Make executable
RUN chmod +x /app/kali-mcp/kali_server.py \
    /app/kali-mcp/mcp_server.py \
    /app/start_kali_mcp.sh

# -----------------------------------------------------------------------------
# 5. Expose Ports
# -----------------------------------------------------------------------------
# 5000: REST API (kali_server.py)
# 5001: MCP SSE server (mcp_server.py)
EXPOSE 5000 5001

# -----------------------------------------------------------------------------
# 6. Health Check
# -----------------------------------------------------------------------------
# Check if REST API is responding
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# -----------------------------------------------------------------------------
# 7. Start Script
# -----------------------------------------------------------------------------
CMD ["/app/start_kali_mcp.sh"]
