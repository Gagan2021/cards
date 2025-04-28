FROM golang:1.20-alpine AS builder
WORKDIR /app

# Install build dependencies (if needed)
RUN apk add --no-cache git

# Copy go.mod and go.sum first, then download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy entire source code (including telegram_bot.go, main.go, .env, etc.)
COPY . .

# Build the binary for Linux with CGO disabled
RUN CGO_ENABLED=0 GOOS=linux go build -o social-card-generator .

# Use a lightweight alpine image for runtime
FROM alpine:3.18
RUN apk --no-cache add ca-certificates
WORKDIR /root/

# Copy the built binary and .env file from the builder stage
COPY --from=builder /app/social-card-generator .
COPY --from=builder /app/.env .

EXPOSE 8080
CMD ["./social-card-generator"]