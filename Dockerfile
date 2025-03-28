FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o beacon .

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/beacon .
COPY certs/ /app/certs/
RUN chmod 644 /app/certs/fullchain.pem && \
    chmod 600 /app/certs/privkey.pem
EXPOSE 443
CMD ["./beacon"]
