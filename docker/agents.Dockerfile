# =============================================================================
# VT-SaiBER Agents Dockerfile
# =============================================================================
# This Dockerfile creates the environment for running your Python agents
#
# What it does:
#   1. Starts from Python 3.11
#   2. Installs system dependencies
#   3. Installs Python packages from requirements.txt
#   4. Sets up the environment
#
# Built by: docker-compose build agents

# -----------------------------------------------------------------------------
# Base Image
# -----------------------------------------------------------------------------
# Use official Python 3.11 slim image
# "slim" variant is smaller (fewer system packages)
FROM python:3.11-slim

# -----------------------------------------------------------------------------
# Install System Dependencies
# -----------------------------------------------------------------------------
# Install system tools that might be needed
RUN apt-get update && \
    apt-get install -y \
    curl \
    git \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# What gets installed:
# - curl: For testing MCP connections
# - git: In case you need to clone anything

# -----------------------------------------------------------------------------
# Set Working Directory
# -----------------------------------------------------------------------------
WORKDIR /app

# -----------------------------------------------------------------------------
# Install Python Dependencies
# -----------------------------------------------------------------------------
# Copy requirements.txt first (Docker caching optimization)
# If requirements.txt doesn't change, this layer is cached
COPY requirements.txt /app/requirements.txt

# Install Python packages
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# What gets installed (from requirements.txt):
# - langchain, langgraph: For agent orchestration
# - ai: API Clients
# - psycopg2-binary: PostgreSQL client
# - httpx: HTTP client for MCP calls
# - pydantic: Data validation
# ... and more (see requirements.txt)

# -----------------------------------------------------------------------------
# Note: Source Code
# -----------------------------------------------------------------------------
# Source code is mounted as a volume in docker-compose.yml
# This allows live editing without rebuilding the image
# See volumes: ./src:/app/src:rw

# -----------------------------------------------------------------------------
# Default Command
# -----------------------------------------------------------------------------
# This is the command that runs when container starts
# Can be overridden in docker-compose.yml
CMD ["python", "src/main.py"]

# How it works:
# 1. Container starts
# 2. Python runs src/main.py
# 3. main.py initializes LangGraph and starts agents
# 4. Agents make HTTP calls to kali-mcp and msf-mcp