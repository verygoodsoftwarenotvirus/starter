PWD                           := $(shell pwd)
MYSELF                        := $(shell id -u)
MY_GROUP					  := $(shell id -g)
GOPATH                        := $(GOPATH)
ARTIFACTS_DIR                 := artifacts
COVERAGE_OUT                  := $(ARTIFACTS_DIR)/coverage.out
GO_FORMAT                     := gofmt -s -w
THIS                          := github.com/verygoodsoftwarenotvirus/starter
TOTAL_PACKAGE_LIST            := `go list $(THIS)/...`
TESTABLE_PACKAGE_LIST         := `go list $(THIS)/... | grep -Ev '(cmd|integration|mock|fakes|converters|utils|generated)'`
ENVIRONMENTS_DIR              := environments
TEST_DOCKER_COMPOSE_FILES_DIR := $(ENVIRONMENTS_DIR)/testing/compose_files
GENERATED_QUERIES_DIR         := internal/database/postgres/generated
SQL_GENERATOR_IMAGE           := sqlc/sqlc:1.25.0
LINTER_IMAGE                  := golangci/golangci-lint:v1.56.1
CONTAINER_LINTER_IMAGE        := openpolicyagent/conftest:v0.49.1
CLOUD_JOBS                    := search_data_index_scheduler
CLOUD_FUNCTIONS               := data_changes outbound_emailer search_indexer webhook_executor
WIRE_TARGETS                  := server/http/build

## non-PHONY folders/files

clean:
	rm -rf $(ARTIFACTS_DIR)

$(ARTIFACTS_DIR):
	@mkdir --parents $(ARTIFACTS_DIR)

clean-$(ARTIFACTS_DIR):
	@rm -rf $(ARTIFACTS_DIR)

.PHONY: setup
setup: $(ARTIFACTS_DIR) revendor rewire configs

## prerequisites

.PHONY: ensure_wire_installed
ensure_wire_installed:
ifeq (, $(shell which wire))
	$(shell go install github.com/google/wire/cmd/wire@latest)
endif

.PHONY: ensure_fieldalignment_installed
ensure_fieldalignment_installed:
ifeq (, $(shell which fieldalignment))
	$(shell go install golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest)
endif

.PHONY: ensure_tagalign_installed
ensure_tagalign_installed:
ifeq (, $(shell which tagalign))
	$(shell go install github.com/4meepo/tagalign/cmd/tagalign@latest)
endif

.PHONY: ensure_gci_installed
ensure_gci_installed:
ifeq (, $(shell which gci))
	$(shell go install github.com/daixiang0/gci@latest)
endif

.PHONY: ensure_sqlc_installed
ensure_sqlc_installed:
ifeq (, $(shell which sqlc))
	$(shell go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest)
endif

.PHONY: ensure_scc_installed
ensure_scc_installed:
ifeq (, $(shell which scc))
	$(shell go install github.com/boyter/scc@latest)
endif

.PHONY: clean_vendor
clean_vendor:
	rm -rf vendor go.sum

vendor:
	if [ ! -f go.mod ]; then go mod init; fi
	go mod tidy
	go mod vendor
	for thing in $(CLOUD_FUNCTIONS); do \
  		(cd cmd/functions/$$thing && go mod tidy) \
	done
	for thing in $(CLOUD_JOBS); do \
  		(cd cmd/jobs/$$thing && go mod tidy) \
	done

.PHONY: revendor
revendor: clean_vendor vendor

## dependency injection

.PHONY: rewire
rewire:
	for tgt in $(WIRE_TARGETS); do \
		rm -f $(THIS)/internal/$$tgt/wire_gen.go && wire gen $(THIS)/internal/$$tgt; \
	done

## formatting

.PHONY: format
format: format_golang terraformat

.PHONY: format_golang
format_golang: format_imports ensure_fieldalignment_installed ensure_tagalign_installed
	@until fieldalignment -fix ./...; do true; done > /dev/null
	@until tagalign -fix -sort -order "json,toml" ./...; do true; done > /dev/null
	for file in `find $(PWD) -type f -not -path '*/vendor/*' -name "*.go"`; do $(GO_FORMAT) $$file; done

.PHONY: format_imports
format_imports: ensure_gci_installed
	gci write --skip-generated --section standard --section "prefix($(THIS))" --section "prefix($(dir $(THIS)))" --section default --custom-order `find $(PWD) -type f -not -path '*/vendor/*' -name "*.go"`

.PHONY: terraformat
terraformat:
	@touch environments/dev/terraform/service-config.json
	@touch environments/dev/terraform/worker-config.json
	@(cd environments/dev/terraform && terraform fmt)

.PHONY: lint_terraform
lint_terraform: terraformat
	@(cd environments/dev/terraform && terraform init -upgrade && terraform validate && terraform fmt && terraform fmt -check)

.PHONY: fmt
fmt: format terraformat

## Testing things

.PHONY: pre_lint
pre_lint:
	@until fieldalignment -fix ./...; do true; done > /dev/null
	@echo ""

.PHONY: lint_docker
lint_docker:
	@docker pull --quiet $(CONTAINER_LINTER_IMAGE)
	docker run --rm --volume $(PWD):$(PWD) --workdir=$(PWD) --user $(MYSELF):$(MY_GROUP) $(CONTAINER_LINTER_IMAGE) test --policy docker_security.rego `find . -type f -name "*.Dockerfile"`

.PHONY: queries_lint
queries_lint:
	@docker pull --quiet $(SQL_GENERATOR_IMAGE)
	docker run --rm \
		--volume $(PWD):/src \
		--workdir /src \
		--user $(MYSELF):$(MY_GROUP) \
		$(SQL_GENERATOR_IMAGE) compile --no-remote
	docker run --rm \
		--volume $(PWD):/src \
		--workdir /src \
		--user $(MYSELF):$(MY_GROUP) \
		$(SQL_GENERATOR_IMAGE) vet --no-remote

.PHONY: golang_lint
golang_lint:
	@docker pull --quiet $(LINTER_IMAGE)
	docker run --rm \
		--volume $(PWD):$(PWD) \
		--workdir=$(PWD) \
		$(LINTER_IMAGE) golangci-lint run --config=.golangci.yml --timeout 15m ./...

.PHONY: lint
lint: lint_docker queries_lint golang_lint

.PHONY: clean_coverage
clean_coverage:
	@rm --force $(COVERAGE_OUT) profile.out;

.PHONY: coverage
coverage: clean_coverage $(ARTIFACTS_DIR)
	@go test -coverprofile=$(COVERAGE_OUT) -shuffle=on -covermode=atomic -race $(TESTABLE_PACKAGE_LIST) > /dev/null
	@go tool cover -func=$(ARTIFACTS_DIR)/coverage.out | grep 'total:' | xargs | awk '{ print "COVERAGE: " $$3 }'

.PHONY: build
build:
	go build $(TOTAL_PACKAGE_LIST)

.PHONY: test
test: $(ARTIFACTS_DIR) vendor build
	go test -cover -shuffle=on -race -vet=all -failfast $(TESTABLE_PACKAGE_LIST)

## Generated files

.PHONY: configs
configs:
	go run $(THIS)/cmd/tools/gen_configs

.PHONY: queries
queries:
	go run $(THIS)/cmd/tools/gen_queries

clean_ts:
	rm -rf $(ARTIFACTS_DIR)/typescript

typescript: clean_ts
	mkdir --parents $(ARTIFACTS_DIR)/typescript
	go run $(THIS)/cmd/tools/codegen/gen_typescript
	(cd ../frontend && make format)

.PHONY: querier
querier: queries queries_lint
	rm --recursive --force internal/database/postgres/generated/*.go
	docker run --rm \
		--volume $(PWD):/src \
		--workdir /src \
		--user $(MYSELF):$(MY_GROUP) \
	$(SQL_GENERATOR_IMAGE) generate --no-remote

.PHONY: sqlc_struct_check
sqlc_struct_check:
	go run $(THIS)/cmd/tools/sqlcstructchecker

## Integration tests

.PHONY: wipe_docker
wipe_docker:
	@docker stop $(shell docker ps -aq) && docker rm $(shell docker ps -aq)

.PHONY: docker_wipe
docker_wipe: wipe_docker

.PHONY: integration-tests
integration-tests: integration_tests

.PHONY: integration_tests
integration_tests: integration_tests_postgres

.PHONY: integration_tests_postgres
integration_tests_postgres:
	docker-compose \
	--file $(TEST_DOCKER_COMPOSE_FILES_DIR)/integration-tests.yaml up \
	--build \
	--force-recreate \
	--remove-orphans \
	--attach-dependencies \
	--pull always \
	--always-recreate-deps \
	$(if $(filter y Y yes YES true TRUE plz sure yup YUP,$(LET_HANG)),,--abort-on-container-exit) \
	--renew-anon-volumes

## Running

.PHONY: dev
dev: $(ARTIFACTS_DIR)
	docker-compose \
	--file $(ENVIRONMENTS_DIR)/local/compose_files/docker-compose.yaml up \
	--quiet-pull \
	--no-recreate \
	--always-recreate-deps

## misc

.PHONY: tree
tree:
	# there are no longargs for tree, but d means "directories only" and I means "ignore pattern"
	tree -d -I vendor

.PHONY: line_count
line_count: ensure_scc_installed
	@scc --include-ext go --exclude-dir vendor

## maintenance

# https://cloud.google.com/sql/docs/postgres/connect-admin-proxy#connect-tcp
.PHONY: proxy_dev_db
proxy_dev_db:
	cloud_sql_proxy project-name:us-central1:dev --port 5434

