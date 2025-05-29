# Build stage
FROM registry.access.redhat.com/ubi9/go-toolset:1.21 AS builder
WORKDIR /go/src/github.com/k37y/gvs
COPY . .
USER root
RUN go build -buildvcs=false -o /usr/bin/gvs ./cmd/gvs
RUN go build -buildvcs=false -o /usr/bin/cg ./cmd/cg

# Final stage
FROM registry.access.redhat.com/ubi9:latest

ENV GOPATH=/go
ENV PATH=${PATH}:${GOPATH}/bin
ENV PATH=${PATH}:/go/src/github.com/k37y/gvs/bin
ENV INSTALL_PKGS="git golang gpgme-devel jq"

WORKDIR /go/src/github.com/k37y/gvs

RUN yum install -y ${INSTALL_PKGS} && \
    go install golang.org/x/vuln/cmd/govulncheck@latest && \
    go install golang.org/x/tools/cmd/callgraph@latest && \
    go install golang.org/x/tools/cmd/digraph@latest

EXPOSE 8082

COPY --from=builder /usr/bin/gvs /go/src/github.com/k37y/gvs/bin/gvs
COPY --from=builder /usr/bin/cg /go/src/github.com/k37y/gvs/bin/cg
COPY --from=builder /go/src/github.com/k37y/gvs/hack/callgraph.sh /go/src/github.com/k37y/gvs/hack/callgraph.sh
COPY --from=builder /go/src/github.com/k37y/gvs/site/index.html /go/src/github.com/k37y/gvs/site/index.html
COPY --from=builder /go/src/github.com/k37y/gvs/site/styles.css /go/src/github.com/k37y/gvs/site/styles.css
COPY --from=builder /go/src/github.com/k37y/gvs/site/script.js /go/src/github.com/k37y/gvs/site/script.js

ENTRYPOINT ["gvs"]
