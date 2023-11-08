//go:generate protoc --proto_path=. --go_out=,paths=source_relative:. msp_principal.proto identities.proto msp_config.proto

package msp