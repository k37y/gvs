# Build stage
FROM registry.access.redhat.com/ubi9/go-toolset:1.21 AS builder
WORKDIR /go/src/github.com/k37y/gvs
COPY . .
RUN go build -o /usr/bin/gvs -buildvcs=false .

# Final stage
FROM registry.access.redhat.com/ubi9:latest
ENV GOPATH=/go
ENV PATH=${PATH}:${GOPATH}/bin
ENV PATH=${PATH}:/go/src/github.com/k37y/gvs

WORKDIR /go/src/github.com/k37y/gvs

RUN yum install -y git golang gpgme-devel && \
    go install golang.org/x/vuln/cmd/govulncheck@latest

EXPOSE 8082

COPY --from=builder /usr/bin/gvs /go/src/github.com/k37y/gvs/gvs
COPY --from=builder /go/src/github.com/k37y/gvs/site/index.html /go/src/github.com/k37y/gvs/site/index.html

ENTRYPOINT ["/go/src/github.com/k37y/gvs/gvs"]
