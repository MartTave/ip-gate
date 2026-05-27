.PHONY: test build vet ci hooks help

test:
	go test ./... -count=1 -race -shuffle=on

build:
	go build ./...

vet:
	go vet ./...

ci: build vet test

hooks:
	git config core.hooksPath .githooks

help:
	@grep -E '^[a-zA-Z_-]+:' Makefile | sort | sed 's/:.*//'
