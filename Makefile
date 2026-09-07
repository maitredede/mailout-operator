# mailout-operator

SHELL := /bin/bash
BIN := $(CURDIR)/bin
IMG ?= ghcr.io/maitredede/mailout-operator:dev
ENVTEST_K8S_VERSION ?= 1.34.0

.PHONY: all
all: generate manifests build test

## --- code generation -------------------------------------------------------

.PHONY: generate
generate: ## deepcopy funcs
	go tool controller-gen object:headerFile=hack/boilerplate.go.txt paths=./api/... paths=./internal/certmanager/...

.PHONY: manifests
manifests: ## CRDs, RBAC, webhook manifests
	go tool controller-gen crd rbac:roleName=mailout-operator webhook \
		paths=./api/... paths=./internal/... output:crd:artifacts:config=config/crd/bases

## --- build -----------------------------------------------------------------

.PHONY: build
build:
	go build -o $(BIN)/mailout ./cmd/mailout

.PHONY: docker-build
docker-build:
	docker build -t $(IMG) .

## --- test ------------------------------------------------------------------

.PHONY: test
test: ## unit tests (no docker, no cluster)
	go test ./... -count=1

.PHONY: test-envtest
test-envtest: ## controller and webhook tests against a local control plane
	KUBEBUILDER_ASSETS="$$(go tool setup-envtest use $(ENVTEST_K8S_VERSION) -p path)" \
		go test ./internal/controller/... ./internal/webhook/... -count=1 -tags=envtest

.PHONY: test-e2e
test-e2e: ## testcontainers end-to-end (needs a docker daemon)
	go test ./test/e2e/... -count=1 -tags=e2e -timeout=20m

.PHONY: test-cluster
test-cluster: manifests ## the whole operator against a throwaway k3s (needs a docker daemon)
	docker build -t mailout-operator:test .
	MAILOUT_TEST_IMAGE=mailout-operator:test \
		go test ./test/cluster/... -count=1 -tags=cluster -timeout=30m

.PHONY: lint
lint:
	go vet ./...
	gofmt -l -d .

## --- local compose ---------------------------------------------------------

.PHONY: compose-certs
compose-certs:
	./deploy/compose/gen-certs.sh

.PHONY: compose-up
compose-up: compose-certs
	docker compose -f deploy/compose/docker-compose.yaml up --build -d

.PHONY: compose-down
compose-down:
	docker compose -f deploy/compose/docker-compose.yaml down -v

## --- deploy ----------------------------------------------------------------

.PHONY: install
install: manifests ## CRDs only
	go tool kustomize build config/crd | kubectl apply -f -

.PHONY: deploy
deploy: manifests ## the whole operator; needs cert-manager for the webhook certificate
	cd config/default && go tool kustomize edit set image ghcr.io/maitredede/mailout-operator=$(IMG)
	go tool kustomize build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy:
	go tool kustomize build config/default | kubectl delete --ignore-not-found -f -

.PHONY: help
help:
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'
