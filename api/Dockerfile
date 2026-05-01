# Stage 1: Builder
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /vpn-manager ./cmd/server

# Stage 2: Runtime (scratch — minimal, ~15MB binary)
FROM scratch

COPY --from=builder /vpn-manager /app/vpn-manager
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080

ENTRYPOINT ["/app/vpn-manager"]
