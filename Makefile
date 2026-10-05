GVS_SOURCES = $(wildcard *.go cmd/gvs/*.go)
CG_SOURCES = $(wildcard cmd/cg/*.go)
NAME = gvs
RUNNING_CONTAINER = $(shell podman ps --format json | jq -r '.[] | select(.Names[] | contains("$(NAME)")) | .Names[]')
VERSION = $(shell git describe --tags --long --dirty 2>/dev/null)
IMAGE = quay.io/k37y/${NAME}:${VERSION}
PORT ?= 8082
ALGO ?= vta
# Optional runtime environment file for AI, MCP, and task settings; never baked into the image.
AI_ENV_FILE ?= $(HOME)/.config/gvs/gvs.env
AI_ENV_VARS = GVS_AI GVS_AI_PROVIDER GVS_AI_MODEL GVS_AI_API_KEY GVS_AI_BASE_URL \
              GVS_AI_PROJECT_ID GVS_AI_LOCATION GVS_AI_MAX_ITERATIONS GVS_AI_MAX_TOKENS GVS_AI_CONTEXT_TOKENS GVS_AI_TIMEOUT GVS_AI_PRICING
# Forward explicitly exported settings; the server supplies defaults for unset variables.
RUNTIME_ENV_VARS = $(AI_ENV_VARS) GVS_MCP GVS_MCP_ALLOWED_ORIGINS GVS_PUBLIC_URL \
                   GVS_SCAN_TIMEOUT GVS_TASK_TTL
ADC_CREDS = $(HOME)/.config/gcloud/application_default_credentials.json
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
UNITDIR ?= /etc/systemd/system
SERVICE = gvs.service
BINS = gvs cg
USERNAME ?= gvs
GROUPNAME ?= $(USERNAME)

# Install test tools in plain UBI; Go selects the module's toolchain automatically.
PODMAN_TEST_IMAGE ?= registry.access.redhat.com/ubi9/ubi
# Keep build/module caches between disposable test containers.
PODMAN_TEST_CACHE ?= gvs-test-cache
# Override to select packages, test names, or a different timeout.
PODMAN_TEST_ARGS ?= -race -v -count=1 -timeout=120s ./...
# Match the host API/scanner and MCP integration suite, with an override for focused runs.
PODMAN_INTEGRATION_TEST_ARGS ?= -race -v -count=1 -tags integration ./internal/api ./internal/mcp -run "TestCallgraph.*Integration|TestCgBinaryValidation|TestMCP.*Integration" -timeout 45m

# Share the read-only checkout and persistent Go caches across both test targets.
PODMAN_TEST_RUN = podman run --rm --security-opt label=disable --user 0 \
	--volume "$(CURDIR):/workspace:ro" \
	--volume "$(PODMAN_TEST_CACHE):/cache" \
	--workdir /workspace \
	--env CGO_ENABLED=1 --env GOTOOLCHAIN=auto \
	--env GOCACHE=/cache/build --env GOMODCACHE=/cache/mod \
	--env GOFLAGS=-buildvcs=false

RUN_OPTS := --security-opt label=disable \
            --rm --detach \
            --name $(NAME)-$(VERSION) \
            --tty \
	    --interactive \
            --publish $(PORT):8082

ifeq ($(shell id -u),0)
	SUDO :=
else
	SUDO := sudo
endif

.PHONY: run

run: gvs cg
	PATH="$(CURDIR)/bin:$$PATH" ./bin/gvs

.PHONY: test

test:
	go test -race -v -count=1 ./...

# Run race tests without requiring Go, CGO, or a C compiler on the host.
.PHONY: test-podman

test-podman:
	$(PODMAN_TEST_RUN) "$(PODMAN_TEST_IMAGE)" sh -c \
		'dnf install -y golang gcc git && exec go test "$$@"' sh $(PODMAN_TEST_ARGS)

.PHONY: test-integration

test-integration:
	@echo "Running integration tests..."
	go test -race -v -count=1 -tags integration ./internal/api ./internal/mcp -run "TestCallgraph.*Integration|TestCgBinaryValidation|TestMCP.*Integration" -timeout 45m

# Install integration dependencies in UBI without requiring host development tools.
.PHONY: test-integration-podman

test-integration-podman:
	$(PODMAN_TEST_RUN) "$(PODMAN_TEST_IMAGE)" sh -c \
		'dnf install -y golang gcc git graphviz && exec go test "$$@"' sh $(PODMAN_INTEGRATION_TEST_ARGS)

.PHONY: gvs

gvs: $(GVS_SOURCES)
	go build -buildvcs=false -ldflags "-X main.version=${VERSION}" -o ./bin/$@ ./cmd/gvs

.PHONY: cg

cg: $(CG_SOURCES)
	go build -buildvcs=false -ldflags "-X main.version=${VERSION}" -o ./bin/$@ ./cmd/cg

.PHONY: image

image:
	@BUILD_ARGS="--build-arg ALGO=$(ALGO)"; \
	echo "Using ALGO=$(ALGO)"; \
	if [ -n "$(WORKER_COUNT)" ]; then \
		echo "Using WORKER_COUNT=$(WORKER_COUNT)"; \
		BUILD_ARGS="$$BUILD_ARGS --build-arg WORKER_COUNT=$(WORKER_COUNT)"; \
	else \
		echo "No WORKER_COUNT provided, building with default (#cpu/2)"; \
	fi; \
	if [ -n "$(CORS_ALLOWED_ORIGINS)" ]; then \
		echo "Using CORS_ALLOWED_ORIGINS=$(CORS_ALLOWED_ORIGINS)"; \
		BUILD_ARGS="$$BUILD_ARGS --build-arg CORS_ALLOWED_ORIGINS=$(CORS_ALLOWED_ORIGINS)"; \
	else \
		echo "No CORS_ALLOWED_ORIGINS provided, using default (same-origin only)"; \
	fi; \
	if [ -n "$(GVS_COUNTER_URL)" ]; then \
		echo "Using GVS_COUNTER_URL=$(GVS_COUNTER_URL)"; \
		BUILD_ARGS="$$BUILD_ARGS --build-arg GVS_COUNTER_URL=$(GVS_COUNTER_URL)"; \
	else \
		echo "No GVS_COUNTER_URL provided, using default"; \
	fi; \
	podman build $$BUILD_ARGS --no-cache --file Dockerfile --tag ${IMAGE}

.PHONY: image-run

image-run: image
	-podman kill ${RUNNING_CONTAINER} && podman wait ${RUNNING_CONTAINER}
	@set --; \
	if [ -f "$(AI_ENV_FILE)" ]; then \
		set -- "$$@" --env-file "$(AI_ENV_FILE)"; \
	fi; \
	for name in $(RUNTIME_ENV_VARS); do \
		if printenv "$$name" >/dev/null; then \
			set -- "$$@" --env "$$name"; \
		fi; \
	done; \
	if [ -f "$(ADC_CREDS)" ]; then \
		set -- "$$@" --volume "$(ADC_CREDS):/root/.config/gcloud/application_default_credentials.json:ro"; \
	fi; \
	podman run $(RUN_OPTS) "$$@" $(IMAGE)

.PHONY: image-push

image-push:
	@if [ -z "$${REGISTRY_AUTH_FILE}" ]; then \
		echo "ERROR: REGISTRY_AUTH_FILE is not set. Please export it before running make image"; \
		exit 1; \
	fi; \
	BUILD_ARGS="--build-arg ALGO=$(ALGO)"; \
	echo "Using ALGO=$(ALGO)"; \
	if [ -n "$(WORKER_COUNT)" ]; then \
		echo "Using WORKER_COUNT=$(WORKER_COUNT)"; \
		BUILD_ARGS="$$BUILD_ARGS --build-arg WORKER_COUNT=$(WORKER_COUNT)"; \
	else \
		echo "No WORKER_COUNT provided, building with default (#cpu/2)"; \
	fi; \
	if [ -n "$(CORS_ALLOWED_ORIGINS)" ]; then \
		echo "Using CORS_ALLOWED_ORIGINS=$(CORS_ALLOWED_ORIGINS)"; \
		BUILD_ARGS="$$BUILD_ARGS --build-arg CORS_ALLOWED_ORIGINS=$(CORS_ALLOWED_ORIGINS)"; \
	else \
		echo "No CORS_ALLOWED_ORIGINS provided, using default (same-origin only)"; \
	fi; \
	if [ -n "$(GVS_COUNTER_URL)" ]; then \
		echo "Using GVS_COUNTER_URL=$(GVS_COUNTER_URL)"; \
		BUILD_ARGS="$$BUILD_ARGS --build-arg GVS_COUNTER_URL=$(GVS_COUNTER_URL)"; \
	else \
		echo "No GVS_COUNTER_URL provided, using default"; \
	fi; \
	podman build $$BUILD_ARGS --no-cache --file Dockerfile --tag ${IMAGE}
	podman push --authfile ${REGISTREY_AUTH_FILE} ${IMAGE}

.PHONY: set-image-ocp

set-image-ocp:
	oc set image deployment/gvs gvs=$$(echo ${IMAGE}@$$(/usr/bin/skopeo inspect docker://${IMAGE} | jq -r .Digest))

install: useradd gvs.service image
	@echo "Installing systemd service to $(UNITDIR)..."
	$(SUDO) install -Dm644 $(SERVICE) $(DESTDIR)$(UNITDIR)/$(SERVICE)
	@echo "Creating latest tag and loading image for root user..."
	podman tag $(IMAGE) quay.io/k37y/gvs:latest
	podman save quay.io/k37y/gvs:latest | $(SUDO) podman load
	@echo "Reloading systemd daemon..."
	$(SUDO) systemctl daemon-reload
	@echo "Enabling and starting service..."
	$(SUDO) systemctl enable --now $(SERVICE)

uninstall: userdel
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

# User-level installation (no sudo required)
USER_BINDIR = $(HOME)/.local/bin
USER_DATADIR = $(HOME)/.local/share/gvs
USER_UNITDIR = $(HOME)/.config/systemd/user
USER_CONFDIR = $(HOME)/.config/gvs
USER_SERVICE = gvs-user.service

.PHONY: install-user

install-user: gvs cg
	@echo "Installing binaries to $(USER_BINDIR)..."
	install -d $(USER_BINDIR)
	install -m755 ./bin/gvs $(USER_BINDIR)/gvs
	install -m755 ./bin/cg $(USER_BINDIR)/cg
	@echo "Installing site files to $(USER_DATADIR)/site..."
	install -d $(USER_DATADIR)/site
	install -m644 ./site/index.html $(USER_DATADIR)/site/
	install -m644 ./site/styles.css $(USER_DATADIR)/site/
	install -m644 ./site/script.js $(USER_DATADIR)/site/
	install -m644 ./site/config.js $(USER_DATADIR)/site/
	@echo "Installing skills to $(USER_DATADIR)/skills..."
	install -d $(USER_DATADIR)/skills
	install -m644 ./skills/verify-scan.md $(USER_DATADIR)/skills/
	@echo "Installing systemd user service to $(USER_UNITDIR)..."
	install -d $(USER_UNITDIR)
	install -m644 $(USER_SERVICE) $(USER_UNITDIR)/gvs.service
	@echo "Creating config directory $(USER_CONFDIR)..."
	install -d $(USER_CONFDIR)
	@if [ ! -f $(USER_CONFDIR)/gvs.env ]; then \
		echo "# GVS configuration" > $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_PORT=8082" >> $(USER_CONFDIR)/gvs.env; \
		echo "# WORKER_COUNT=4" >> $(USER_CONFDIR)/gvs.env; \
		echo "# ALGO=vta" >> $(USER_CONFDIR)/gvs.env; \
		echo "# CORS_ALLOWED_ORIGINS=" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_COUNTER_URL=" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_MCP=1" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_MCP_ALLOWED_ORIGINS=" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_PUBLIC_URL=" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_SCAN_TIMEOUT=30m" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_TASK_TTL=24h" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_AI=1" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_AI_PROVIDER=openai-compatible" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_AI_MODEL=" >> $(USER_CONFDIR)/gvs.env; \
		echo "# GVS_AI_API_KEY=" >> $(USER_CONFDIR)/gvs.env; \
	fi
	@echo "Reloading systemd user daemon..."
	systemctl --user daemon-reload
	@echo ""
	@echo "Installation complete!"
	@echo "To enable and start the service:"
	@echo "  systemctl --user enable --now gvs"
	@echo ""
	@echo "To enable service at boot (without login):"
	@echo "  make enable-linger"

.PHONY: uninstall-user

uninstall-user:
	@echo "Stopping and disabling user service..."
	-systemctl --user disable --now gvs || true
	@echo "Removing binaries..."
	rm -f $(USER_BINDIR)/gvs $(USER_BINDIR)/cg
	@echo "Removing data directory..."
	rm -rf $(USER_DATADIR)
	@echo "Removing systemd user service..."
	rm -f $(USER_UNITDIR)/gvs.service
	@echo "Reloading systemd user daemon..."
	systemctl --user daemon-reload
	@echo "Uninstall complete."
	@echo "Note: Config directory $(USER_CONFDIR) was preserved."

.PHONY: enable-linger

enable-linger:
	@echo "Enabling linger for user $(shell whoami)..."
	loginctl enable-linger $(shell whoami)
	@echo "Linger enabled. Service will start at boot without login."

.PHONY: disable-linger

disable-linger:
	@echo "Disabling linger for user $(shell whoami)..."
	loginctl disable-linger $(shell whoami)
	@echo "Linger disabled."
