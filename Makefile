.PHONY: run

run: build
	./gvs

.PHONY: build

build:
	go build -o gvs main.go

.PHONY: image

image:
	podman build -f Dockerfile -t quay.io/kevy/gvs:v1
	podman push --authfile ~/.kevy-kevy.json quay.io/kevy/gvs:v1

.PHONY: redeploy

redeploy:
	oc set image deployment/gvs gvs=$$(echo quay.io/kevy/gvs@$$(/usr/bin/skopeo inspect docker://quay.io/kevy/gvs:v1 | jq -r .Digest))
