//go:generate protoc --proto_path=. --go_out=plugins=grpc,paths=source_relative:. message.proto

package pbgossip
