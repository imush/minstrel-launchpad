FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/minstrel-launchpad .

# Nothing but the binary: it only talks HTTP on the LAN and serves its own
# self-signed HTTPS, so it needs no CA bundle or shell.
FROM scratch
COPY --from=build /out/minstrel-launchpad /minstrel-launchpad
ENV LAUNCHPAD_DATA=/data
VOLUME /data
EXPOSE 7443 7444
ENTRYPOINT ["/minstrel-launchpad"]
CMD ["serve"]
