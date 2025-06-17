default: build

buildarm64:
	-rm ./bin/gradius.arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ./bin/gradius.arm64 ./cmds/gradius/main.go
	-upx -9 ./bin/gradius.arm64

build:
	-rm ./bin/gradius
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/gradius ./cmds/gradius/main.go
	-upx -9 ./bin/gradius

clean:
	-rm ./bin -rf