# ==============================================================================
# Vardhan Q-Core :: Multi-Stage Zero-Trust Air-Gapped Scanner Container
# Compliant with PRD L-02, CIS Docker Benchmark, and Bank Hardening Standards
# ==============================================================================

# Stage 1: Build the static, CGO-free single binary
FROM golang:1.26-alpine AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates git

# Cache go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and rules
COPY . .

# Compile 100% static binary with stripped debug symbols
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /bin/qcore cmd/qcore/main.go

# Stage 2: Minimal Zero-Vulnerability Runtime Image
FROM alpine:3.20 AS runtime

LABEL maintainer="Vardhan Technologies <security@vardhan.co>"
LABEL description="Vardhan Q-Core Air-Gapped Cryptographic Discovery & CBOM Engine"
LABEL spec.cyclonedx="1.6"

# Create unprivileged dedicated service user
RUN addgroup -g 10001 -S qcore && \
    adduser -u 10001 -S qcore -G qcore -s /sbin/nologin && \
    mkdir -p /workspace /reports /keys /config /tmp && \
    chown -R qcore:qcore /workspace /reports /keys /config /tmp

# Copy static binary from builder
COPY --from=builder /bin/qcore /usr/local/bin/qcore
RUN chmod 0555 /usr/local/bin/qcore

# Default non-root user
USER 10001:10001

# Volumes for air-gapped file mounting
VOLUME ["/workspace", "/reports", "/keys", "/config"]

# Working directory
WORKDIR /workspace

# Invariants for air-gapped runtime
ENV TMPDIR=/tmp \
    QCORE_OFFLINE=1

ENTRYPOINT ["/usr/local/bin/qcore"]
CMD ["scan", "/workspace", "-f", "table"]
