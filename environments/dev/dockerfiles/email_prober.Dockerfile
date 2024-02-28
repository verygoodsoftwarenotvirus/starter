# build stage
FROM golang:1.22-bullseye AS build-stage

WORKDIR /go/src/github.com/verygoodsoftwarenotvirus/starter

COPY . .

RUN go build -trimpath -o /action github.com/verygoodsoftwarenotvirus/starter/cmd/jobs/email_prober

# final stage
FROM debian:bullseye

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
COPY --from=build-stage /action /action

ENTRYPOINT ["/action"]
