# Stage 1: Build frontend (SolidJS → dist/)
FROM node:24-alpine AS frontend-builder
WORKDIR /frontend
COPY internal/web/frontend/package*.json ./
RUN npm ci
COPY internal/web/frontend/ ./
RUN npm run build

# Stage 2: Build Go binary (embeds frontend/dist at compile time)
FROM golang:1.26-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /frontend/dist ./internal/web/frontend/dist
RUN go build -o server ./cmd/server

# Stage 3: Minimal runtime image
FROM alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab
RUN apk upgrade --no-cache && apk add --no-cache poppler-utils ca-certificates
WORKDIR /app
COPY --from=go-builder /app/server .
VOLUME ["/data"]
EXPOSE 8080
CMD ["./server"]
