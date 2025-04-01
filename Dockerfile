# Build stage
FROM registry.access.redhat.com/ubi9/go-toolset:1.21 AS builder
WORKDIR /go/src/github.com/k37y/gvs
COPY . .
RUN go build -o /usr/bin/gvs -buildvcs=false .

# Final stage
FROM registry.access.redhat.com/ubi9:latest
ENV GOPATH=/go
ENV PATH=${PATH}:${GOPATH}/bin

# Install dependencies and govulncheck
RUN yum install -y git golang && \
    go install golang.org/x/vuln/cmd/govulncheck@latest

EXPOSE 8082

# Copy the built binary
COPY --from=builder /usr/bin/gvs /usr/bin/gvs

ENTRYPOINT ["/usr/bin/gvs"]
