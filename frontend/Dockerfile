FROM golang:1.5-alpine

ADD . /go/src/app
RUN go install app

VOLUME ["/ssl"]

CMD /go/bin/app
EXPOSE 8080
