# Multi-stage build → tiny distroless image. The Svelte portal is committed
# under portal/dist and embedded via go:embed, so the Go build is fully
# self-contained (no Node stage needed).
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/entra-emulator ./cmd/entra-emulator
# Pre-create the data dir so it can be copied in with nonroot ownership
# (distroless has no shell to chown at runtime).
RUN mkdir -p /out/data

# distroless static: no shell, non-root, minimal attack surface. The pure-Go
# SQLite driver means no libc is required.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/entra-emulator /usr/local/bin/entra-emulator
# State (SQLite DB + persisted TLS cert) lives here; mount a volume to persist.
# Copied with nonroot ownership (65532) so the unprivileged user can write.
COPY --from=build --chown=65532:65532 /out/data /app/data
VOLUME ["/app/data"]
ENV HOST=0.0.0.0 ORIGIN_MODE=compat DB_PATH=/app/data/entra-emulator.db TLS_CERT_DIR=/app/data/tls
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/entra-emulator", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/entra-emulator"]
