FROM golang:latest

RUN go get github.com/google/identity-toolkit-go-client/gitkit
RUN go get github.com/gorilla/securecookie
RUN go get github.com/unrolled/secure

ADD . /go/src/app
RUN go install app

VOLUME ["/ssl", "/oauth"]

CMD /go/bin/app
EXPOSE 8080
