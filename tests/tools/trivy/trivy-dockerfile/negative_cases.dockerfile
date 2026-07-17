FROM golang:1.22-alpine

RUN go build -o /app ./cmd/server

CMD ["/app"]
