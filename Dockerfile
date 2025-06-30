FROM scratch
COPY go-wire /
ENTRYPOINT ["/go-wire"]
