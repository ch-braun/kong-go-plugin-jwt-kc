# Description: Dockerfile for building Kong with custom plugin

ARG GO_VERSION="1.23"
ARG KONG_VERSION="3.7"

# Build custom plugins
FROM golang:${GO_VERSION} AS builder

COPY ./ /plugins

WORKDIR /plugins

RUN mkdir -p /plugins/out

RUN go build -o /plugins/out/go-jwt-kc go-jwt-kc.plugin.go
    # Check if plugin was built successfully
RUN if [ ! -f /plugins/out/go-jwt-kc ]; then exit 1; fi;

FROM kong:${KONG_VERSION}

USER root

# Assemble Kong with custom plugins
COPY --from=builder /plugins/out /usr/local/bin/kong-plugins

RUN chmod +x /usr/local/bin/kong-plugins/*

ENV KONG_PLUGINS="bundled,go-jwt-kc"

ENV KONG_PLUGINSERVER_NAMES="go-jwt-kc"

ENV KONG_PLUGINSERVER_GO_JWT_KC_SOCKET="/usr/local/kong/go-jwt-kc.socket"
ENV KONG_PLUGINSERVER_GO_JWT_KC_START_CMD="/usr/local/bin/kong-plugins/go-jwt-kc"
ENV KONG_PLUGINSERVER_GO_JWT_KC_QUERY_CMD="/usr/local/bin/kong-plugins/go-jwt-kc -dump"

# Reset back to the defaults
USER kong
#ENTRYPOINT ["/docker-entrypoint.sh"]
#EXPOSE 8000 8443 8001 8444
#STOPSIGNAL SIGQUIT
#HEALTHCHECK --interval=10s --timeout=10s --retries=10 CMD kong health
#CMD ["kong", "docker-start"]