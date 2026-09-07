# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/mailout ./cmd/mailout

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mailout /usr/local/bin/mailout
USER 65532:65532
EXPOSE 587 465
ENTRYPOINT ["/usr/local/bin/mailout"]
CMD ["gateway"]
