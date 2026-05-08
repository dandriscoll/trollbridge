# syntax=docker/dockerfile:1
#
# Multi-stage build of trollbridge as a static binary.
# The runtime stage is `scratch`; the resulting image is small
# (~10 MB) and has no shell or package manager attack surface.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/trollbridge \
    ./cmd/trollbridge

FROM scratch
# Trust roots for origin TLS verification. Override at deploy time
# if you need a corporate CA.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/trollbridge /usr/local/bin/trollbridge

# Default config & audit log paths; mount over /etc/trollbridge and
# /var/log/trollbridge.
EXPOSE 8080 8081
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/trollbridge"]
CMD ["run", "--config", "/etc/trollbridge/trollbridge.yaml"]
