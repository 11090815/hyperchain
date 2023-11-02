package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/11090815/hyperchain/protos-go/test/proto"
	"google.golang.org/grpc"
)

type Client struct {
	greeterClient    proto.GreeterClient
	downloaderClient proto.DownloaderClient
}

func NewClient(address string) (*Client, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	greeterClient := proto.NewGreeterClient(conn)
	downloaderClient := proto.NewDownloaderClient(conn)

	return &Client{greeterClient: greeterClient, downloaderClient: downloaderClient}, nil
}

func (c *Client) SayHello() error {
	resp, err := c.greeterClient.SayHello(context.Background(), &proto.HelloRequest{Name: "Tom"})
	if err != nil {
		return err
	}

	fmt.Printf("Greet to server successfully, response from server: [%s]\n", resp.Payload)
	return nil
}

func (c *Client) Download() error {
	stream, err := c.downloaderClient.Download(context.Background(), &proto.DownloadRequest{Suffix: ".jpg"})
	if err != nil {
		return err
	}

	hasReceived := make(map[string]*os.File)

	path := filepath.Join("download")
	_, err = os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		fmt.Println(2222, path)
		if err = os.Mkdir(path, os.FileMode(0755)); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		os.RemoveAll(filepath.Join(path, entry.Name()))
	}

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if file, ok := hasReceived[resp.Name]; !ok {
			newFile, err := os.Create(filepath.Join(path, resp.Name))
			if err != nil {
				return err
			}
			defer newFile.Close()
			if _, err = newFile.Write(resp.Payload); err != nil {
				return err
			}
			hasReceived[resp.Name] = newFile
		} else {
			if len(resp.Payload) == 0 {
				fmt.Printf("Download [%s] completed.\n", resp.Name)
			} else {
				if _, err = file.Write(resp.Payload); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func main() {
	client, err := NewClient("192.168.189.128:8080")
	if err != nil {
		panic(err)
	}

	if err = client.SayHello(); err != nil {
		panic(err)
	}

	if err = client.Download(); err != nil {
		panic(err)
	}
}
