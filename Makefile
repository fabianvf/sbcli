SOURCE_DIRS      = cmd
SOURCES          := $(shell find . -name '*.go' -not -path "*/vendor/*")
.DEFAULT_GOAL    := sbcli

sbcli: $(SOURCES) ## Build the samplebroker
	go build -i -ldflags="-s -w"

lint: ## Run golint
	@golint -set_exit_status $(addsuffix /... , $(SOURCE_DIRS))

fmtcheck: ## Check go formatting
	@gofmt -l $(SOURCES) | grep ".*\.go"; if [ "$$?" = "0" ]; then exit 1; fi

test: ## Run unit tests
	@go test -cover ./cmd/...

vet: ## Run go vet
	@go tool vet ./cmd

check: fmtcheck vet lint sbcli test ## Pre-flight checks before creating PR

clean: ## Clean up your working environment
	@rm -f sbcli

help: ## Show this help screen
	@echo 'Usage: make <OPTIONS> ... <TARGETS>'
	@echo ''
	@echo 'Available targets are:'
	@echo ''
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ''

.PHONY: clean lint build fmtcheck test vet help
