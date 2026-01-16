# Build stage
FROM registry.access.redhat.com/ubi9/go-toolset:1.23 AS builder
WORKDIR /go/src/github.com/k37y/gvs
COPY . .
USER root
RUN go build -buildvcs=false -o /go/src/github.com/k37y/gvs/bin/gvs ./cmd/gvs
RUN go build -buildvcs=false -o /go/src/github.com/k37y/gvs/bin/cg ./cmd/cg

# Final stage
FROM quay.io/fedora/fedora:latest

ARG WORKER_COUNT
ARG ALGO
ARG CORS_ALLOWED_ORIGINS
ARG GVS_COUNTER_URL

ENV WORKER_COUNT=${WORKER_COUNT}
ENV ALGO=${ALGO}
ENV CORS_ALLOWED_ORIGINS=${CORS_ALLOWED_ORIGINS}
ENV GVS_COUNTER_URL=${GVS_COUNTER_URL}
ENV GOPATH=/go
ENV PATH=${PATH}:${GOPATH}/bin
ENV PATH=${PATH}:/go/src/github.com/k37y/gvs/bin
ENV INSTALL_PKGS="git golang gpgme-devel jq libseccomp-devel btrfs-progs-devel"

WORKDIR /go/src/github.com/k37y/gvs

RUN yum install -y ${INSTALL_PKGS} && \
    go install golang.org/x/vuln/cmd/govulncheck@latest && \
    go install golang.org/x/tools/cmd/callgraph@latest && \
    go install golang.org/x/tools/cmd/digraph@latest

EXPOSE 8082

COPY --from=builder /go/src/github.com/k37y/gvs/bin/gvs /go/src/github.com/k37y/gvs/bin/gvs
COPY --from=builder /go/src/github.com/k37y/gvs/bin/cg /go/src/github.com/k37y/gvs/bin/cg
COPY --from=builder /go/src/github.com/k37y/gvs/site/index.html /go/src/github.com/k37y/gvs/site/index.html
COPY --from=builder /go/src/github.com/k37y/gvs/site/styles.css /go/src/github.com/k37y/gvs/site/styles.css
COPY --from=builder /go/src/github.com/k37y/gvs/site/script.js /go/src/github.com/k37y/gvs/site/script.js
COPY --from=builder /go/src/github.com/k37y/gvs/site/config.js /go/src/github.com/k37y/gvs/site/config.js

ENTRYPOINT ["gvs"]
