FROM golang:1.20-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o social-card-generator main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/social-card-generator .
COPY fonts/ ./fonts/
RUN mkdir -p cards
EXPOSE 8080
CMD ["./social-card-generator"]