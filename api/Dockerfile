# Stage 1: Builder
FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /vpn-manager ./cmd/server

# Stage 2: Runtime (alpine — minimal OS for healthcheck and debugging)
FROM alpine:3.19

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /vpn-manager /app/vpn-manager

EXPOSE 8080

ENTRYPOINT ["/app/vpn-manager"]
