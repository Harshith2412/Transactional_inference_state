FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pytest curl jq libcap2-bin procps iproute2 ca-certificates \
    gzip build-essential pkg-config protobuf-compiler protobuf-c-compiler libprotobuf-c-dev \
    libprotobuf-dev libnl-3-dev libnet1-dev libcap-dev libaio-dev \
    libgnutls28-dev uuid-dev python3-protobuf python3-yaml asciidoc xmlto && \
    rm -rf /var/lib/apt/lists/*

ARG CRIU_VERSION=4.2.1
ARG DMTCP_VERSION=4.2.0
RUN curl -fsSL "https://github.com/checkpoint-restore/criu/archive/refs/tags/v${CRIU_VERSION}.tar.gz" \
      -o /tmp/criu.tar.gz && \
    tar -xzf /tmp/criu.tar.gz -C /tmp && \
    make -C "/tmp/criu-${CRIU_VERSION}" -j2 && \
    make -C "/tmp/criu-${CRIU_VERSION}" install PREFIX=/usr/local && \
    curl -fsSL "https://github.com/dmtcp/dmtcp/archive/refs/tags/v${DMTCP_VERSION}.tar.gz" \
      -o /tmp/dmtcp.tar.gz && \
    tar -xzf /tmp/dmtcp.tar.gz -C /tmp && \
    cd "/tmp/dmtcp-${DMTCP_VERSION}" && ./configure --prefix=/usr/local && \
    make -j2 && make install && \
    rm -rf /tmp/criu* /tmp/dmtcp*

WORKDIR /workspace
ENV PYTHONPATH=/workspace/src
CMD ["bash"]
