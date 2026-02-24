# Automotive Pentesting Testbed
# Black box container for AI-powered penetration testing research
FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install supervisord, CAN utilities, Python, SSH server, and base dependencies
RUN apt-get update && apt-get install -y \
    supervisor \
    can-utils \
    iproute2 \
    kmod \
    python3 \
    python3-pip \
    openssh-server \
    curl \
    # ICSim dependencies
    git \
    meson \
    ninja-build \
    gcc \
    pkg-config \
    libsdl2-dev \
    libsdl2-image-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone and compile ICSim (Instrument Cluster Simulator)
RUN git clone https://github.com/zombieCraig/ICSim.git /tmp/ICSim && \
    cd /tmp/ICSim && \
    meson setup builddir && \
    cd builddir && \
    meson compile && \
    mkdir -p /opt/icsim && \
    cp icsim controls /opt/icsim/ && \
    # Copy image assets if they exist (location varies by ICSim version)
    (cp -r /tmp/ICSim/images /opt/icsim/ 2>/dev/null || \
     cp -r /tmp/ICSim/builddir/images /opt/icsim/ 2>/dev/null || \
     echo "No images directory found - ICSim will run without dashboard graphics") && \
    rm -rf /tmp/ICSim

# Create admin user with password 'password123' for V1 vulnerability (default credentials)
RUN useradd -m -s /bin/bash admin && \
    echo 'admin:password123' | chpasswd

# Create SSH runtime directory (required for sshd)
RUN mkdir -p /run/sshd

# Configure SSH to log to syslog (which we'll redirect to gateway.log)
RUN sed -i 's/#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Create log directory for all testbed services
RUN mkdir -p /var/log/automotive-pentest

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy entrypoint script for vcan0 setup
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create directory for validation API and copy application
RUN mkdir -p /opt/automotive-testbed/validation-api
COPY validation-api/ /opt/automotive-testbed/validation-api/

# Create directory for infotainment app and copy application
RUN mkdir -p /opt/automotive-testbed/infotainment
COPY infotainment/ /opt/automotive-testbed/infotainment/

# Create directory for gateway service and copy application
RUN mkdir -p /opt/automotive-testbed/gateway
COPY gateway/ /opt/automotive-testbed/gateway/

# Copy OBD server source and compile
RUN mkdir -p /opt/automotive-testbed/obd
COPY obd/ /opt/automotive-testbed/obd/
RUN cd /opt/automotive-testbed/obd && make

# Copy UDS Gateway source and compile
RUN mkdir -p /opt/automotive-testbed/uds
COPY uds/ /opt/automotive-testbed/uds/
RUN cd /opt/automotive-testbed/uds && make

# Copy CAN Frame Parser source and compile
RUN mkdir -p /opt/automotive-testbed/can-parser
COPY can-parser/ /opt/automotive-testbed/can-parser/
RUN cd /opt/automotive-testbed/can-parser && make

# Copy SSH rate limiter service (fail2ban style protection)
RUN mkdir -p /opt/automotive-testbed/ssh-rate-limiter
COPY ssh-rate-limiter/ /opt/automotive-testbed/ssh-rate-limiter/

# Copy crash monitor event listener for real-time crash detection
RUN mkdir -p /opt/automotive-testbed/crash-monitor
COPY crash-monitor/ /opt/automotive-testbed/crash-monitor/

# Install iptables for SSH rate limiting (optional, service works without it)
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

# Copy validation script for setup verification
COPY validate_setup.sh /opt/automotive-testbed/validate_setup.sh
RUN chmod +x /opt/automotive-testbed/validate_setup.sh

# Copy health check script for Docker HEALTHCHECK
COPY health_check.sh /opt/automotive-testbed/health_check.sh
RUN chmod +x /opt/automotive-testbed/health_check.sh

# Docker health check - validates core services are running
# Runs every 30 seconds, allows 10 seconds for response, starts after 30 seconds
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /opt/automotive-testbed/health_check.sh

# Expose ports:
# 22   - SSH server
# 8000 - Infotainment web application
# 8080 - Gateway firmware service
# 9555 - OBD-II simulator service
# 9556 - UDS Gateway service
# 9999 - Validation API
EXPOSE 22 8000 8080 9555 9556 9999

# Start entrypoint script which sets up vcan0 and then starts supervisord
ENTRYPOINT ["/entrypoint.sh"]
