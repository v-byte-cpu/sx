FROM golang:1.25-alpine AS builder

ARG VERSION=dev
ARG COMMIT

RUN apk add --no-cache libpcap-dev libc-dev gcc linux-headers
ADD . /app
WORKDIR /app
RUN go build \
    -buildvcs=false \
    -trimpath \
    -ldflags "-w -s -linkmode external -extldflags '-static' -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /sx

FROM alpine:3.24

COPY --from=builder /sx /sx
ENTRYPOINT ["/sx"]
