static-check:
	go vet ./...
	golangci-lint run

test: static-check
	go test ./... -vet=all -race -cover -coverprofile=coverage.out

all: static-check test
