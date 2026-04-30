FROM kalilinux/kali-rolling:latest

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 \
    python3-pip \
    curl \
    bash \
    git \
    netcat-traditional \
    openssh-client \
    sshpass \
    ruby \
    build-essential \
    postgresql-client \
    nmap \
    gobuster \
    ffuf \
    dirb \
    nikto \
    sqlmap \
    hydra \
    john \
    wordlists \
    seclists \
    wpscan \
    enum4linux \
    enum4linux-ng \
    whatweb \
    metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then \
        gzip -dk /usr/share/wordlists/rockyou.txt.gz; \
    fi

WORKDIR /app

RUN pip3 install --no-cache-dir --break-system-packages \
    "mcp>=1.0.0" \
    "fastapi>=0.110.0" \
    "starlette>=0.36.0" \
    "uvicorn>=0.27.0" \
    "httpx>=0.27.0" \
    "requests>=2.31.0" \
    "pymetasploit3>=0.2.17" \
    "pydantic>=2.6.0"

COPY scripts/docker/patch_metasploit_http_cookie_jar.sh /app/patch_metasploit_http_cookie_jar.sh
RUN chmod +x /app/patch_metasploit_http_cookie_jar.sh && \
    /app/patch_metasploit_http_cookie_jar.sh

COPY scripts/docker/start_attackbox.sh /app/start_attackbox.sh
RUN chmod +x /app/start_attackbox.sh

EXPOSE 55553 8080

HEALTHCHECK --interval=15s --timeout=10s --start-period=90s --retries=5 \
    CMD nc -z localhost 8080 || exit 1

CMD ["/app/start_attackbox.sh"]
