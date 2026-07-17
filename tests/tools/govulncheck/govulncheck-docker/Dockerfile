FROM golang:1.22

WORKDIR /app
COPY . .

RUN govulncheck ./...
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

CMD ["govulncheck", "./..."]
ENTRYPOINT ["govulncheck", "-test"]
