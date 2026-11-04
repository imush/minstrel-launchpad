FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION -X main.packaging=docker" \
        -o /out/minstrel-launchpad .

# ffmpeg rides along so compression works the moment the container starts.
# Without it nothing breaks -- lossless tracks are simply sent as they are --
# but a Docker user has no way to install it afterwards, so leaving it out
# means the console reports "not available" on every NAS forever.
# tzdata gives the logs the local time rather than UTC.
FROM alpine:3.21
RUN apk add --no-cache ffmpeg tzdata
COPY --from=build /out/minstrel-launchpad /usr/local/bin/minstrel-launchpad
ENV LAUNCHPAD_DATA=/data
VOLUME /data
EXPOSE 7443 7444
ENTRYPOINT ["/usr/local/bin/minstrel-launchpad"]
CMD ["serve"]
