.PHONY: build generate clean

build:
	go build -o minimal-fxa-server .
	go build -o fxa-user ./cmd/fxa-user

generate:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		usermgmt/usermgmt.proto

clean:
	rm -f minimal-fxa-server fxa-user

