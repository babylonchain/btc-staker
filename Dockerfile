FROM golang:1.21-alpine as builder

# Version to build. Default is the Git HEAD.
ARG VERSION="HEAD"

# Use muslc for static libs
ARG BUILD_TAGS="muslc"


RUN apk add --no-cache --update openssh git make build-base linux-headers libc-dev \
                                pkgconfig zeromq-dev musl-dev alpine-sdk libsodium-dev \
                                libzmq-static libsodium-static gcc

# Build
WORKDIR /go/src/github.com/babylonchain/btc-staker
# Cache dependencies
COPY go.mod go.sum /go/src/github.com/babylonchain/btc-staker/
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

RUN addgroup --gid 1138 -S btcstaker && adduser --uid 1138 -S btcstaker -G btcstaker

RUN apk add bash curl jq

COPY --from=builder /go/src/github.com/babylonchain/btc-staker/build/stakerd /bin/stakerd
COPY --from=builder /go/src/github.com/babylonchain/btc-staker/build/stakercli /bin/stakercli

WORKDIR /home/btcstaker
RUN chown -R btcstaker /home/btcstaker
USER btcstaker

ENTRYPOINT ["/bin/stakerd"]
CMD []
STOPSIGNAL SIGTERM
