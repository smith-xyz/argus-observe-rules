FROM golang:1.22

WORKDIR /app
RUN go build -o /app/bin ./cmd/...
