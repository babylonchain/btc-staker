FROM golang:1.20.5-alpine as builder

# Version to build. Default is the Git HEAD.
ARG VERSION="HEAD"

# Use muslc for static libs
ARG BUILD_TAGS="muslc"

ARG GITHUB_ACCESS_TOKEN

RUN apk add --no-cache --update openssh git make build-base linux-headers libc-dev \
                                pkgconfig zeromq-dev musl-dev alpine-sdk libsodium-dev \
                                libzmq-static libsodium-static gcc

# this is needed as we are using private repos as our dependencies
RUN git config --global url."https://${GITHUB_ACCESS_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/"

# Build
WORKDIR /go/src/github.com/babylonchain/btc-staker
# Cache dependencies
COPY go.mod go.sum /go/src/github.com/babylonchain/btc-staker/
RUN go mod download
# Copy the rest of the files
COPY ./ /go/src/github.com/babylonchain/btc-staker/

# Cosmwasm - Download correct libwasmvm version
RUN WASMVM_VERSION=$(go list -m github.com/CosmWasm/wasmvm | cut -d ' ' -f 2) && \
    wget https://github.com/CosmWasm/wasmvm/releases/download/$WASMVM_VERSION/libwasmvm_muslc.$(uname -m).a \
        -O /lib/libwasmvm_muslc.a && \
    # verify checksum
    wget https://github.com/CosmWasm/wasmvm/releases/download/$WASMVM_VERSION/checksums.txt -O /tmp/checksums.txt && \
    sha256sum /lib/libwasmvm_muslc.a | grep $(cat /tmp/checksums.txt | grep libwasmvm_muslc.$(uname -m) | cut -d ' ' -f 1)

RUN CGO_LDFLAGS="$CGO_LDFLAGS -lstdc++ -lm -lsodium" \
    CGO_ENABLED=1 \
    BUILD_TAGS=$BUILD_TAGS \
    LINK_STATICALLY=true \
    make build

# FINAL IMAGE
FROM alpine:3.16 AS run

# Define a root volume for data persistence.
VOLUME /root/.stakerd

RUN apk add bash curl jq

COPY --from=builder /go/src/github.com/babylonchain/btc-staker/build/stakerd /bin/
COPY --from=builder /go/src/github.com/babylonchain/btc-staker/build/stakercli /bin/

# Default staker rpc port
EXPOSE 15812

ENTRYPOINT ["stakerd"]
