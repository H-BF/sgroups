ARG GO_VER=1.22
ARG ALPINE_VER=3.20
ARG ALPINE_MIRROR=https://mirror.yandex.ru/mirrors/alpine/v${ALPINE_VER}/main

# first build stage
# by default uses alpine-based image
FROM golang:${GO_VER}-alpine${ALPINE_VER} as builder

# copy all source code for build
WORKDIR /src

# install updates and build executable
RUN apk upgrade --no-cache -X ${ALPINE_MIRROR} && \
    apk add make git

COPY . .

RUN make .install-goose

# second release stage
FROM alpine:${ALPINE_VER}

# create user other than root and install updated
RUN addgroup -g 101 app && \
    adduser -H -u 101 -G app -s /bin/sh -D app && \
    apk update --no-cache -X ${ALPINE_MIRROR} && \
    apk upgrade --no-cache -X ${ALPINE_MIRROR}

# place all necessary executables and other files into /app directory
WORKDIR /app/
RUN mkdir -p /app/bin
COPY --from=builder --chown=app:app /src/bin/ /app/bin/
COPY --from=builder --chown=app:app /src/internal/registry/sgroups/pg/migrations/ /app/

# run container as new non-root user
USER app

CMD ["/app/bin/goose"]