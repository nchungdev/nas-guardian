-include config.mk

NAS_HOST ?= nas.local
NAS_USER ?= $(USER)
BINARY_NAME = nas-guardian

.PHONY: all build build-linux deploy status logs restart

all: build

build:
	go build -ldflags="-s -w" -o bin/$(BINARY_NAME) main.go

build-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/$(BINARY_NAME)-linux main.go

deploy: build-linux
	scp bin/$(BINARY_NAME)-linux $(NAS_USER)@$(NAS_HOST):/tmp/$(BINARY_NAME)
	ssh -o BatchMode=yes $(NAS_USER)@$(NAS_HOST) "sudo mv /tmp/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME) && sudo chmod +x /usr/local/bin/$(BINARY_NAME) && sudo systemctl restart nas-guardian"
	@echo "Deployment successful. Service restarted."

status:
	ssh -o BatchMode=yes $(NAS_USER)@$(NAS_HOST) "sudo systemctl status nas-guardian --no-pager"

logs:
	ssh -t -o BatchMode=yes $(NAS_USER)@$(NAS_HOST) "sudo journalctl -u nas-guardian -f"

restart:
	ssh -o BatchMode=yes $(NAS_USER)@$(NAS_HOST) "sudo systemctl restart nas-guardian"
