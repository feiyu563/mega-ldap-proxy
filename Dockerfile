FROM golang:1.16-alpine3.12 as builder

WORKDIR $GOPATH/src/github.com/feiyu563/mega-ldap-proxy

RUN apk update && apk upgrade && apk add --no-cache gcc g++ sqlite-libs

ENV GO111MODULE on

ENV GOPROXY https://goproxy.io

COPY . $GOPATH/src/github.com/feiyu563/mega-ldap-proxy

RUN go mod vendor && go build

# -----------------------------------------------------------------------------

FROM alpine:3.12

LABEL maintainer="jikun.zhang"

RUN apk update && apk upgrade && apk add --no-cache sqlite-libs

WORKDIR /app

COPY --from=builder /go/src/github.com/feiyu563/mega-ldap-proxy/mega-ldap-proxy .

COPY db db

COPY conf conf

COPY proxystatic proxystatic

COPY views views

COPY logs logs

CMD [ "./mega-ldap-proxy" ]