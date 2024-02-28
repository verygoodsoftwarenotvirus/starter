# syntax=docker/dockerfile:1
FROM golang:1.22-bullseye

WORKDIR /go/src/github.com/verygoodsoftwarenotvirus/starter

COPY . .

RUN go build -o /server github.com/verygoodsoftwarenotvirus/starter/cmd/services/api/http

ENTRYPOINT /server
