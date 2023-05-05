bin_dir := bin
src := $(wildcard src/*.go)
target := $(bin_dir)/aes-demo

all: $(target)

$(bin_dir):
	@mkdir $(bin_dir)

$(target): $(src) | $(bin_dir)
	@go build -o $(target)

clean: | $(bin_dir)
	@rm -rf $(bin_dir)
lint:
	@golangci-lint run
format:
	@go fmt
vet:
	@go vet

.PHONY: all lint vet clean
