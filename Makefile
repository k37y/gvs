.PHONY: run

run: build
	./gvs

.PHONY: build

build:
	go build -o gvs main.go
