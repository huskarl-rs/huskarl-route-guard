FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
WORKDIR /fixture
ENV GOTOOLCHAIN=local
COPY go.mod main.go ./
RUN test -z "$(gofmt -l main.go)" && go vet ./... && CGO_ENABLED=0 go build -trimpath -o /server .

FROM scratch
COPY --from=build /server /server
ENV GODEBUG=httpmuxgo121=0
USER 65534:65534
ENTRYPOINT ["/server"]
