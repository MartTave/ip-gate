# Multi-stage build for minimal Docker image
FROM golang:alpine AS builder

WORKDIR /app

# Copy go mod and source
COPY go.mod go.sum ./
COPY src/ ./src/

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ttl-allow-service ./src/cmd/server

# Final minimal image
FROM scratch

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/ttl-allow-service .

# Expose default port
EXPOSE 8080

# Run the binary
CMD ["./ttl-allow-service"]
