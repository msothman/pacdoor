# =============================================================================
# PACDOOR - Automated Red Team Penetration Testing Tool
# Multi-stage Docker build
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM python:3.13-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml ./
COPY README.md ./
COPY src/ ./src/

# Install pacdoor with all optional dependencies into a virtual env
RUN python -m venv /opt/pacdoor-venv && \
    /opt/pacdoor-venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/pacdoor-venv/bin/pip install --no-cache-dir ".[all]"

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM python:3.13-slim

LABEL maintainer="pacdoor"
LABEL description="PACDOOR - Automated Red Team Penetration Testing Tool"

# Install runtime dependencies
#   - nmap: SYN scan, OS fingerprinting, NSE scripts
#   - libpcap0.8: required by nmap for raw packet capture
#   - libffi8: required by cryptography
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        libpcap0.8 \
        libffi8 && \
    rm -rf /var/lib/apt/lists/*

# Copy the virtual env from the builder stage
COPY --from=builder /opt/pacdoor-venv /opt/pacdoor-venv

# Create a non-root user for security
RUN groupadd -r pacdoor && \
    useradd -r -g pacdoor -m -s /bin/bash pacdoor

# Create output directory and set permissions
RUN mkdir -p /results && chown pacdoor:pacdoor /results

# Add the venv to PATH
ENV PATH="/opt/pacdoor-venv/bin:${PATH}"
ENV PYTHONUNBUFFERED=1

# Output directory as a volume mount point
VOLUME ["/results"]

# Switch to non-root user
USER pacdoor
WORKDIR /home/pacdoor

# Default entrypoint runs pacdoor with --no-tui (no terminal in Docker)
# and writes output to /results
ENTRYPOINT ["python", "-m", "pacdoor", "--no-tui", "--output-dir", "/results"]

# Default command shows help if no arguments provided
CMD ["--help"]
