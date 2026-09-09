# syntax=docker/dockerfile:1

# Pinned by digest, not by tag: golang:1.27-alpine moves, so the bytes audited
# today are not the bytes rebuilt tomorrow. Both digests are OCI image indexes,
# so the build stays multi-arch — the cluster this runs on is mostly arm64 with
# a single amd64 node.
#
# To bump: docker buildx imagetools inspect <image>:<tag> and take the index
# Digest. Never take a per-platform manifest digest, that pins one architecture.
# --platform=$BUILDPLATFORM plus GOARCH below: the toolchain runs natively and
# cross-compiles, instead of the whole build stage running under QEMU for the
# foreign architecture. This cluster is three arm64 workers and one amd64, and
# the operator runs two replicas with only a preferred anti-affinity, so a
# single-arch image means one replica looping on `exec format error`.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/mailout ./cmd/mailout

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/mailout /usr/local/bin/mailout
USER 65532:65532
EXPOSE 587 465
ENTRYPOINT ["/usr/local/bin/mailout"]
CMD ["gateway"]
