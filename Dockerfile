# Build stage
FROM registry.access.redhat.com/ubi9/go-toolset:1.21 AS builder
WORKDIR /go/src/github.com/k37y/gvs
COPY . .
RUN go build -o /usr/bin/gvs -buildvcs=false .

# Final stage
FROM registry.access.redhat.com/ubi9:latest
EXPOSE 8081
COPY --from=builder /usr/bin/gvs /usr/bin/gvs
ENTRYPOINT ["/usr/bin/gvs"]
