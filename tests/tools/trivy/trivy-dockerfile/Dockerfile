FROM alpine:3.19

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
RUN trivy fs --exit-code 1 .

CMD ["sh"]
