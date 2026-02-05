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
# FROM: Starting point (base image)
# We use Kali Linux's official rolling release
FROM kalilinux/kali-rolling:latest

# -----------------------------------------------------------------------------
# Install Dependencies
# -----------------------------------------------------------------------------
# RUN: Execute a command during build
# && chains commands together
# rm -rf /var/lib/apt/lists/* cleans up to reduce image size
RUN apt-get update && \
    apt-get install -y \
    mcp-kali-server \
    curl \
    wordlists \
    nmap \
    arp-scan \
    masscan \
    gobuster \
    ffuf \
    nikto \
    sqlmap \
    hydra \
    john \
    hashcat \
    && rm -rf /var/lib/apt/lists/*

# What gets installed:
# - mcp-kali-server: The pre-built MCP server package
#   - Provides: kali-server-mcp (API server on port 5000)
#   - Provides: mcp-server (MCP client)
# - curl: For health checks and testing

# Unzip rockyou.txt so tools like John, Hydra, and Hashcat can use it immediately
RUN gunzip /usr/share/wordlists/rockyou.txt.gz || true

# -----------------------------------------------------------------------------
# Working Directory
# -----------------------------------------------------------------------------
# WORKDIR: Sets the current directory (like 'cd')
WORKDIR /app

# -----------------------------------------------------------------------------
# Expose Ports
# -----------------------------------------------------------------------------
# EXPOSE: Documents which ports the container uses
# Doesn't actually publish ports - that's done in docker-compose.yml
EXPOSE 5000

# -----------------------------------------------------------------------------
# Startup Command
# -----------------------------------------------------------------------------
# CMD: The command to run when container starts
# This starts the Kali API server on port 5000
CMD ["kali-server-mcp", "--port", "5000", "--ip", "0.0.0.0"]

# How it works:
# When container starts, it runs: kali-server-mcp --port 5000
# This starts an HTTP server that accepts tool requests
# Example: POST http://kali-mcp:5000/tools/nmap