ARG GO_VER
ARG ALPINE_VER

# first build stage
# by default uses alpine-based image
FROM golang:1.20-alpine3.19 as builder

# copy all source code for build
WORKDIR /src
COPY . .

# install updates and build executable
RUN apk upgrade --no-cache -X https://mirror.yandex.ru/mirrors/alpine/v3.19/main && \
    apk add make git && \
    make .install-goose

# second release stage
FROM alpine:3.19

# create user other than root and install updated
RUN addgroup -g 101 app && \
    adduser -H -u 101 -G app -s /bin/sh -D app && \
    apk update --no-cache -X https://mirror.yandex.ru/mirrors/alpine/v3.19/main && \
    apk upgrade --no-cache -X https://mirror.yandex.ru/mirrors/alpine/v3.19/main

# place all necessary executables and other files into /app directory
WORKDIR /app/
RUN mkdir -p /app/bin
COPY --from=builder --chown=app:app /src/bin/ /app/bin/
COPY --from=builder --chown=app:app /src/internal/registry/sgroups/pg/migrations/ /app/

# run container as new non-root user
USER app

CMD ["/app/bin/goose"]