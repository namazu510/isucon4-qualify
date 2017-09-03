
build:
	go build -o golang-webapp .

format:
	goimports -w .
	go fmt ./...
