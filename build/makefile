build:
	go build -o connector-service ./cmd

docker-build:
	docker build -t connector-service .

run:
	./connector-service

test:
	go test ./...

docker-run:
	docker run -p 8080:8080 connector-service
