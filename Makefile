all: linux windows

linux: bin/logrecv bin/logrecv-client
windows: bin/logrecv.exe bin/logrecv-client.exe

bin/logrecv: bin
	GOOS=linux go build -o $@ ./cmd/logrecv

bin/logrecv-client: bin
	GOOS=linux go build -o $@ ./cmd/logrecv-client

bin/logrecv.exe: bin
	GOOS=windows go build -o $@ ./cmd/logrecv

bin/logrecv-client.exe: bin
	GOOS=windows go build -o $@ ./cmd/logrecv-client

bin:
	mkdir -p bin
