package configtest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func GetDevMspDir() string {
	dir := GetDevConfigDir()
	return filepath.Join(dir, "msp")
}

func GetDevConfigDir() string {
	path, err := gomodDevConfigDir()
	if err != nil {
		path, err = gopathDevConfigDir()
		if err != nil {
			panic(err)
		}
		return path
	}
	return path
}

func gopathDevConfigDir() (string, error) {
	buf := bytes.NewBuffer(nil)
	cmd := exec.Command("go", "env", "GOPATH")
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		return "", err
	}
	gopath := strings.TrimSpace(buf.String())
	for _, path := range filepath.SplitList(gopath) {
		devPath := filepath.Join(path, "src/github.com/11090815/hyperchain/sampleconfig")
		if dirExists(devPath) {
			return devPath, nil
		}
	}

	return "", errors.New("unable to find sampleconfig directory on GOPATH")
}

func gomodDevConfigDir() (string, error) {
	buf := bytes.NewBuffer(nil)
	cmd := exec.Command("go", "env", "GOMOD")
	cmd.Stdout = buf

	if err := cmd.Run(); err != nil {
		return "", err
	}

	modFile := strings.TrimSpace(buf.String())
	if modFile == "" {
		return "", errors.New("not a module or not in module mode")
	}
	devPath := filepath.Join(filepath.Dir(modFile), "sampleconfig")
	if !dirExists(devPath) {
		return "", fmt.Errorf("directory [%s] does not exist", devPath)
	}

	return devPath, nil
}

func dirExists(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil {
		return false
	}
	return fi.IsDir()
}
