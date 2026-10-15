FROM debian:bookworm-slim

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install strongSwan, networking utilities, tcpdump, and python
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    strongswan-starter \
    libstrongswan-standard-plugins \
    libstrongswan-extra-plugins \
    libcharon-extra-plugins \
    iproute2 \
    iptables \
    iputils-ping \
    tcpdump \
    curl \
    kmod \
    procps \
    python3 \
    python3-pip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy application files
COPY testbed/ /app/testbed/
COPY packet_analysis/ /app/packet_analysis/

# Ensure entrypoint is executable
RUN chmod +x /app/testbed/entrypoint.sh

# Captures directory volume
VOLUME ["/captures"]

ENTRYPOINT ["/bin/bash", "/app/testbed/entrypoint.sh"]
