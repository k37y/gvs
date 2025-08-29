GVS_SOURCES = $(wildcard *.go cmd/gvs/*.go)
CG_SOURCES = $(wildcard cmd/cg/*.go)
NAME = gvs
RUNNING_CONTAINER = $(shell podman ps --format json | jq -r '.[] | select(.Names[] | contains("$(NAME)")) | .Names[]')
VERSION = $(shell git describe --tags --long --dirty 2>/dev/null)
IMAGE = quay.io/kevy/${NAME}:${VERSION}
IMAGE_NAME = $(basename $(IMAGE))
PORT ?= 8082
GEMINI_CONF = $(HOME)/.gemini.conf
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
UNITDIR ?= /etc/systemd/system
SERVICE = gvs.service
BINS = bin/gvs bin/cg
USERNAME ?= gvs
GROUPNAME ?= $(USERNAME)

RUN_OPTS := --security-opt label=disable \
            --rm --detach \
            --name $(NAME)-$(VERSION) \
            --tty \
	    --interactive \
            --publish $(PORT):8082

ifdef VOLUME_EXISTS
    VOLUME_OPT := --volume $(GEMINI_CONF):/root/.gemini.conf
endif

ifeq ($(shell id -u),0)
	SUDO :=
else
	SUDO := sudo
endif

.PHONY: run

run: gvs cg
	./bin/gvs

.PHONY: gvs

gvs: $(GVS_SOURCES)
	go build -buildvcs=false -ldflags "-X main.version=${VERSION}" -o ./bin/$@ ./cmd/gvs

.PHONY: cg

cg: $(CG_SOURCES)
	go build -buildvcs=false -ldflags "-X main.version=${VERSION}" -o ./bin/$@ ./cmd/cg

.PHONY: image

image:
	@if [ -n "$(WORKER_COUNT)" ]; then \
		echo "Using WORKER_COUNT=$(WORKER_COUNT)"; \
		podman build --build-arg WORKER_COUNT=$(WORKER_COUNT) --no-cache --file Dockerfile --tag ${IMAGE}; \
	else \
		echo "No WORKER_COUNT provided, building with #cpu/2 ..."; \
		podman build --no-cache --file Dockerfile --tag ${IMAGE}; \
	fi

.PHONY: image-run

image-run: image
	-podman kill ${RUNNING_CONTAINER} && podman wait ${RUNNING_CONTAINER}
	@if [ -f "$(GEMINI_CONF)" ]; then \
		echo "Gemini config found. Mounting volume ..."; \
		VOLUME_OPT="--volume $(GEMINI_CONF):/root/.gemini.conf"; \
	else \
		echo "Gemini config not found. Skipping volume mount ..."; \
		VOLUME_OPT=""; \
	fi; \
	podman run $(RUN_OPTS) $$VOLUME_OPT $(IMAGE)

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

install: cg gvs useradd $(SERVICE)
	@echo "Installing binaries to $(BINDIR)..."
	for bin in $(BINS); do \
		$(SUDO) install -Dm755 $$bin $(DESTDIR)$(BINDIR)/$$bin; \
	done
	@echo "Installing systemd service to $(UNITDIR)..."
	$(SUDO) install -Dm644 $(SERVICE) $(DESTDIR)$(UNITDIR)/$(SERVICE)
	@echo "Reloading systemd daemon..."
	$(SUDO) systemctl daemon-reload
	@echo "Enabling and starting service..."
	$(SUDO) systemctl enable --now $(SERVICE)

uninstall: stop disable userdel
	@echo "Stopping + disabling service..."
	-$(SUDO) systemctl disable --now $(SERVICE) || true
	@echo "Removing binaries..."
	for bin in $(BINS); do \
		$(SUDO) rm -f $(DESTDIR)$(BINDIR)/$$bin; \
	done
	@echo "Removing systemd service..."
	-$(SUDO) rm -f $(DESTDIR)$(UNITDIR)/$(SERVICE)
	@echo "Reloading systemd daemon..."
	$(SUDO) systemctl daemon-reload
	@echo "Removing user..."
	$(MAKE) userdel

useradd:
	@if ! id -u $(USERNAME) >/dev/null 2>&1; then \
		echo "Creating system user: $(USERNAME)"; \
		$(SUDO) useradd --system --no-create-home --shell /usr/sbin/nologin $(USERNAME); \
	fi

userdel:
	@if id -u $(USERNAME) >/dev/null 2>&1; then \
		echo "Removing system user: $(USERNAME)"; \
		$(SUDO) userdel -r $(USERNAME) || true; \
	fi
