build: buildlinux

buildwin64:
	-rm ./bin/gradiuswin64.exe
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ./bin/gradiuswin64.exe ./server/main.go
	-upx -9 ./bin/gradiuswin64.exe

buildlinux:
	-rm ./bin/gradiuslinux
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/gradiuslinux ./server/main.go
	-upx -9 ./bin/gradiuslinux

clean:
	-rm ./bin -rf