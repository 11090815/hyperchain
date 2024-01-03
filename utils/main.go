package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type Result struct {
	FileName string `json:"file_name"`
	Matches  []struct {
		Line    int    `json:"line_num"`
		Content string `json:"content"`
	} `json:"matches"`
}

type View struct {
	Results []*Result `json:"results"`
}

func GetAllFile(pathname string, s []string) ([]string, error) {
	index := strings.LastIndex(pathname, "/")
	if pathname[index+1] == '.' {
		return s, nil
	}
	rd, err := os.ReadDir(pathname)
	if err != nil {
		fmt.Println("read dir fail:", err)
		return s, err
	}
	for _, fi := range rd {
		if fi.IsDir() {
			fullDir := pathname + "/" + fi.Name()
			s, err = GetAllFile(fullDir, s)
			if err != nil {
				fmt.Println("read dir fail:", err)
				return s, err
			}
		} else {
			if strings.LastIndex(fi.Name(), ".json") != -1 {
				continue
			}
			fullName := pathname + "/" + fi.Name()
			s = append(s, fullName)
		}
	}
	return s, nil
}

func SearchTextInFile(filePath string, text string, caseSensitive bool) (*Result, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	perm := fileInfo.Mode().Perm()
	flag := perm & os.FileMode(73)
	if uint32(flag) == uint32(73) {
		return nil, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := &Result{
		FileName: filePath,
		Matches: make([]struct {
			Line    int    "json:\"line_num\""
			Content string "json:\"content\""
		}, 0),
	}

	buffer := bufio.NewReader(file)
	lineNum := 0
	for {
		l, isPrefix, err := buffer.ReadLine()
		if !isPrefix {
			lineNum++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if caseSensitive {
			if strings.Contains(string(l), text) {
				result.Matches = append(result.Matches, struct {
					Line    int    "json:\"line_num\""
					Content string "json:\"content\""
				}{
					Line:    lineNum,
					Content: string(l),
				})
			}
		} else {
			if strings.Contains(strings.ToLower(string(l)), strings.ToLower(text)) {
				result.Matches = append(result.Matches, struct {
					Line    int    "json:\"line_num\""
					Content string "json:\"content\""
				}{
					Line:    lineNum,
					Content: string(l),
				})
			}
		}
	}
	return result, nil
}

func main() {
	var s []string
	s, _ = GetAllFile("/home/iris/research/code/go/src/github.com/11090815/hyperchain", s)
	view := &View{}
	for _, filePath := range s {
		res, err := SearchTextInFile(filePath, "string(", true)
		if err != nil {
			panic(err)
		}
		if res != nil && len(res.Matches) > 0 {
			view.Results = append(view.Results, res)
		}
	}

	raw, err := json.Marshal(view)
	if err != nil {
		panic(err)
	}

	file, err := os.OpenFile(fmt.Sprintf("found:%d.json", time.Now().Unix()), os.O_CREATE|os.O_RDWR, os.FileMode(0600))
	if err != nil {
		panic(err)
	}
	file.Write(raw)
	file.Close()
}
