FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o beacon .

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/beacon .
EXPOSE 8080
CMD ["./beacon"]