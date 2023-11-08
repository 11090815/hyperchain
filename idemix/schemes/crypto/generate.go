//go:generate protoc --proto_path=. --proto_path=$GOPATH/src --go_out=,paths=source_relative:. idemix.proto

package crypto