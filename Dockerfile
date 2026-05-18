FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o server ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache poppler-utils ca-certificates
WORKDIR /app
COPY --from=builder /app/server .
VOLUME ["/data"]
EXPOSE 8080
CMD ["./server"]
