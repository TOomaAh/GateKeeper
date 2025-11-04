# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o gatekeeper \
    ./cmd/gatekeeper

FROM alpine:latest

LABEL org.opencontainers.image.title="GateKeeper"
LABEL org.opencontainers.image.description="Security monitoring and IP blocking system"
LABEL org.opencontainers.image.source="https://github.com/TOomaAh/GateKeeper"

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    sqlite

RUN addgroup -g 1000 gatekeeper && \
    adduser -D -u 1000 -G gatekeeper gatekeeper

RUN mkdir -p /app/data /app/payloads && \
    chown -R gatekeeper:gatekeeper /app

WORKDIR /app

COPY --from=builder /build/gatekeeper .
COPY --from=builder /build/config.yaml.example ./config.yaml.example

USER gatekeeper

EXPOSE 8888 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/stats || exit 1

ENTRYPOINT ["/app/gatekeeper"]
CMD ["-config", "/app/config.yaml"]
