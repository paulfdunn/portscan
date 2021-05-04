FROM golang:1.14.14-buster AS builder
COPY ./src/ /go/src/github.com/paulfdunn/portscan/src/
WORKDIR /go/src/github.com/paulfdunn/portscan/src/
RUN go test -v ./... >test.log 2>&1 
WORKDIR ./portscanservice
RUN CGO_ENABLED=0 GOOS=linux go build
WORKDIR ../portscan
RUN CGO_ENABLED=0 GOOS=linux go build

# New stage to create service container
FROM alpine:3.12.3 AS service
EXPOSE 8000
COPY --from=builder /go/src/github.com/paulfdunn/portscan/src/portscanservice/portscanservice /app/portscanservice
WORKDIR /app
CMD ["./portscanservice"]

# New stage to create cli container
FROM alpine:3.12.3 AS cli
RUN apk --no-cache add curl
# add perl-utils for json_pp
RUN apk --no-cache add perl-utils
COPY --from=builder /go/src/github.com/paulfdunn/portscan/src/portscan/portscan /app/portscan
WORKDIR /app
