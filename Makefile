build: buildlinux

buildwin64:
	-rm ./bin/radiuswin64.exe
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ./bin/radiuswin64.exe ./cmd/server/main.go
	-upx -9 ./bin/radiuswin64.exe

buildlinux:
	-rm ./bin/radiuslinux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/radiuslinux ./cmd/server/main.go
	-upx -9 ./bin/radiuslinux

clean:
	-rm ./bin -rf