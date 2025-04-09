SOURCES=$(wildcard *.go cmd/*/*.go)
VERSION=$(shell git describe --tags --long --dirty 2>/dev/null)

.PHONY: run

run: gvs
	./bin/gvs

.PHONY: gvs

gvs : $(SOURCES)
	go build -ldflags "-X main.version=${VERSION}" -o ./bin/$@ ./cmd/gvs

.PHONY: image

image:
	@if [ -z "$${REGISTREY_AUTH_FILE}" ]; then \
		echo "ERROR: REGISTREY_AUTH_FILE is not set. Please export it before running make image"; \
		exit 1; \
	fi
	podman build -f Dockerfile -t quay.io/kevy/gvs:v1
	podman push --authfile ${REGISTREY_AUTH_FILE} quay.io/kevy/gvs:v1

.PHONY: image-run

image-run: image
	podman run --rm --tty --interactive quay.io/k37y/gvs

.PHONY: set-image-ocp

set-image-ocp:
	oc set image deployment/gvs gvs=$$(echo quay.io/kevy/gvs@$$(/usr/bin/skopeo inspect docker://quay.io/kevy/gvs:v1 | jq -r .Digest))
