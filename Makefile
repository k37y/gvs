SOURCES=$(wildcard *.go cmd/*/*.go)
VERSION=$(shell git describe --tags --long --dirty 2>/dev/null)
IMAGE=quay.io/kevy/gvs:v1
IMAGE_NAME=$(basename $(IMAGE))

.PHONY: run

run: gvs
	./bin/gvs

.PHONY: gvs

gvs : $(SOURCES)
	go build -ldflags "-X main.version=${VERSION}" -o ./bin/$@ ./cmd/gvs

.PHONY: image

image:
	podman build -f Dockerfile -t ${IMAGE}

.PHONY: image-push

image-push:
	@if [ -z "$${REGISTRY_AUTH_FILE}" ]; then \
		echo "ERROR: REGISTRY_AUTH_FILE is not set. Please export it before running make image"; \
		exit 1; \
	fi
	podman build -f Dockerfile -t ${IMAGE}
	podman push --authfile ${REGISTREY_AUTH_FILE} ${IMAGE}

.PHONY: image-run

image-run: image
	podman run --rm --tty --interactive ${IMAGE}

.PHONY: set-image-ocp

set-image-ocp:
	oc set image deployment/gvs gvs=$$(echo ${IMAGE_NAME}@$$(/usr/bin/skopeo inspect docker://${IMAGE} | jq -r .Digest))
