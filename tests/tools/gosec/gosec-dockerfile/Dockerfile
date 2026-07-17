FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
RUN go install github.com/securego/gosec/v2/cmd/gosec@latest
RUN gosec -fmt json -out results.json ./...
