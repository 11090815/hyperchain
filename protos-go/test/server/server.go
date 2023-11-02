package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/11090815/hyperchain/protos-go/test/proto"
	"google.golang.org/grpc"
)

type Server struct {
	server *grpc.Server
}

func (s *Server) SayHello(ctx context.Context, r *proto.HelloRequest) (*proto.HelloReply, error) {
	payload := fmt.Sprintf("Hello, %s.", r.GetName())
	return &proto.HelloReply{Payload: payload}, nil
}

// 服务端流 RPC
func (s *Server) Download(r *proto.DownloadRequest, stream proto.Downloader_DownloadServer) error {
	entries, err := os.ReadDir("pictures")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), r.Suffix) {
			continue
		}

		file, err := os.OpenFile(filepath.Join("pictures", entry.Name()), os.O_RDONLY, os.FileMode(0600))
		if err != nil {
			return err
		}

		for {
			buf := make([]byte, 1024)
			n, err := file.Read(buf)
			if err != nil {
				if err == io.EOF {
					if err = stream.Send(&proto.DownloadResponse{Name: entry.Name(), Payload: nil}); err != nil {
						return err
					}
					break
				} else {
					return err
				}
			}
			if err = stream.Send(&proto.DownloadResponse{Name: entry.Name(), Payload: buf[:n]}); err != nil {
				return err
			}
		}
		fmt.Printf("Successfully transfer file [%s] to client.\n", entry.Name())
	}

	return nil
}

func (s *Server) Start(address string) error {
	
	server := grpc.NewServer()
	s.server = server
	proto.RegisterGreeterServer(server, s)
	proto.RegisterDownloaderServer(server, s)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	return server.Serve(listener)
}

func (s *Server) Stop() {
	s.server.Stop()
}

func main() {
	server := &Server{}
	if err := server.Start("0.0.0.0:8080"); err != nil {
		panic(err)
	}
}
