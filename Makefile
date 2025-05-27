GVS_SOURCES = $(wildcard *.go cmd/gvs/*.go)
CG_SOURCES = $(wildcard cmd/callgraph/*.go)
NAME = gvs
RUNNING_CONTAINER = $(shell podman ps --format json | jq -r '.[] | select(.Names[] | contains("$(NAME)")) | .Names[]')
VERSION = $(shell git describe --tags --long --dirty 2>/dev/null)
IMAGE = quay.io/kevy/${NAME}:${VERSION}
IMAGE_NAME = $(basename $(IMAGE))
PORT ?= 8082

.PHONY: run

run: gvs cg
	./bin/gvs

.PHONY: gvs

gvs: $(GVS_SOURCES)
	go build -buildvcs=false -ldflags "-X main.version=${VERSION}" -o ./bin/$@ ./cmd/gvs

.PHONY: cg

cg: $(CG_SOURCES)
	go build -buildvcs=false -ldflags "-X main.version=${VERSION}" -o ./bin/$@ ./cmd/callgraph

.PHONY: image

image:
	podman build --no-cache --file Dockerfile --tag ${IMAGE}

.PHONY: image-run

image-run: image
	-podman kill ${RUNNING_CONTAINER} && podman wait ${RUNNING_CONTAINER}
	podman run --security-opt label=disable --rm --detach --name ${NAME}-${VERSION} --tty --interactive --publish ${PORT}:8082 --volume ${HOME}/.gemini.conf:/root/.gemini.conf ${IMAGE}

.PHONY: image-push

image-push:
	@if [ -z "$${REGISTRY_AUTH_FILE}" ]; then \
		echo "ERROR: REGISTRY_AUTH_FILE is not set. Please export it before running make image"; \
		exit 1; \
	fi
	podman build --no-cache --file Dockerfile --tag ${IMAGE}
	podman push --authfile ${REGISTREY_AUTH_FILE} ${IMAGE}

.PHONY: set-image-ocp

set-image-ocp:
	oc set image deployment/gvs gvs=$$(echo ${IMAGE_NAME}@$$(/usr/bin/skopeo inspect docker://${IMAGE} | jq -r .Digest))
