//go:generate protoc --proto_path=. --proto_path=$GOPATH/src/ --go_out=,paths=source_relative:. common.proto policies.proto configtx.proto configuration.proto ledger.proto

package pbcommon