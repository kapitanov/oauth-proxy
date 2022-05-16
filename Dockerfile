FROM golang:1.18-alpine As build
WORKDIR /app
ENV CGO_ENABLED=0
COPY go.mod /app/go.mod
RUN go mod download
COPY . /app/
RUN go build -buildvcs=false -o=/out/oauth-proxy

FROM alpine:latest
ENV LISTEN_ADDR=0.0.0.0:80
WORKDIR /opt/oauth-proxy/
COPY --from=build /out/oauth-proxy /opt/oauth-proxy/oauth-proxy
COPY --from=build /app/www /opt/oauth-proxy/www
ENTRYPOINT [ "/opt/oauth-proxy/oauth-proxy" ]
