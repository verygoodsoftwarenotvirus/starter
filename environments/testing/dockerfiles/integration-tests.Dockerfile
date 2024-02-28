# syntax=docker/dockerfile:1
FROM golang:1.22-bullseye

WORKDIR /go/src/github.com/verygoodsoftwarenotvirus/starter
COPY . .

# to debug a specific test:
# ENTRYPOINT go test -parallel 1 -v -failfast github.com/verygoodsoftwarenotvirus/starter/tests/integration -run TestIntegration/TestLogin

ENTRYPOINT go test -v github.com/verygoodsoftwarenotvirus/starter/tests/integration
