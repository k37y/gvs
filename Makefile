GVS_SOURCES=$(wildcard *.go cmd/gvs/*.go)
CG_SOURCES=$(wildcard cmd/callgraph/*.go)
VERSION=$(shell git describe --tags --long --dirty 2>/dev/null)
IMAGE=quay.io/kevy/gvs:${VERSION}
IMAGE_NAME=$(basename $(IMAGE))
PORT=?8082

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
	-podman kill ${VERSION} && podman wait ${VERSION}
	podman run --security-opt label=disable --rm --detach --name ${VERSION} --tty --interactive --publish ${PORT}:8082 ${IMAGE}

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
