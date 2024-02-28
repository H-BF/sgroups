FROM golang:1.20-alpine3.17 as builder
WORKDIR /src
COPY . .
RUN apk upgrade && \
    apk add make git && \
    make .install-goose

FROM alpine:3.17
RUN addgroup -g 101 app && \
    adduser -H -u 101 -G app -s /bin/sh -D app && \
    apk update && apk upgrade
WORKDIR /app/
RUN mkdir -p /app/bin
COPY --from=builder --chown=app:app /src/bin/ /app/bin/
COPY --from=builder --chown=app:app /src/internal/registry/sgroups/pg/migrations/ /app/
USER app
ENTRYPOINT ["/app/bin/goose"]
