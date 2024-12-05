.PHONY: all
all: generate build deploy

.PHONY: generate
generate:
	go generate

.PHONY: build
build:
	go build

.PHONY: deploy
deploy:
	scp * agent1:/root/packet-filter/
	scp * agent2:/root/packet-filter/
