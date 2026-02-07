# =============================================================================
# Kali MCP Server Dockerfile
# =============================================================================
# This Dockerfile creates an image with Kali Linux and the MCP server package
#
# What it does:
#   1. Starts from official Kali Linux image
#   2. Installs mcp-kali-server package
#   3. Configures it to run on port 5000
#
# Built by: docker-compose build kali-mcp

# -----------------------------------------------------------------------------
# Base Image
# -----------------------------------------------------------------------------
FROM kalilinux/kali-rolling:latest

# -----------------------------------------------------------------------------
# Install Dependencies
# -----------------------------------------------------------------------------
# Only install tools that are SUPPORTED by mcp-kali-server:
# dirb, enum4linux, gobuster, hydra, john, metasploit-framework, nikto, nmap, sqlmap, wpscan
RUN apt-get update && \
    apt-get install -y \
    # MCP Server
    mcp-kali-server \
    \
    # --- ACTIVE TOOLS (Keep these) ---
    dirb \
    gobuster \
    nikto \
    nmap \
    sqlmap \
    metasploit-framework \
    \
    # --- UNUSED TOOLS (Commented out to save space) ---
    # enum4linux \
    # hydra \
    # john \
    # wpscan \
    \
    # --- Utilities (Keep these, they are small and useful) ---
    curl \
    wget \
    dnsutils \
    whois \
    wordlists \
    \
    # --- Python for MCP SDK ---
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Unzip rockyou.txt (only needed for john and hyrda)
# RUN gunzip /usr/share/wordlists/rockyou.txt.gz || true

# -----------------------------------------------------------------------------
# Install MCP SDK
# -----------------------------------------------------------------------------
# The mcp_server.py wrapper needs the MCP SDK to expose the REST API via MCP protocol
RUN pip3 install --break-system-packages \
    mcp \
    httpx \
    httpx-sse

# -----------------------------------------------------------------------------
# Working Directory
# -----------------------------------------------------------------------------
WORKDIR /app

# -----------------------------------------------------------------------------
# Copy Startup Script
# -----------------------------------------------------------------------------
COPY scripts/docker/start_kali_mcp.sh /app/start_kali_mcp.sh
RUN chmod +x /app/start_kali_mcp.sh

# -----------------------------------------------------------------------------
# Expose Ports
# -----------------------------------------------------------------------------
EXPOSE 5000

# -----------------------------------------------------------------------------
# Startup Command
# -----------------------------------------------------------------------------
CMD ["/app/start_kali_mcp.sh"]