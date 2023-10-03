#!/bin/bash

# 如果脚本中出现了返回值为非零的错误，脚本就会退出
set -e

# 获取该脚本文件的第一个命令行参数，该参数指定了编译 hyperchain 所需要的 Go 编译器的版本号
CI_VERSION=$1
# 获取本地安装的 Go 编译器的版本号
#   - cut -f3 -d ' '命令：该命令将传入的字符串根据字符 ' ' 进行分割，然后获取分割后的第三个字段
#   - sed 's/^go/python/'命令：该命令首先判断传入的字符是否以 go 开头，如果是的话，则将开头的 go 替换成 python
GO_VERSION="$(go version | cut -f3 -d ' ' | sed 's/^go//')"

fail() {
    # 将错误消息重定向输出到错误流中
    echo "ERROR: go${CI_VERSION} is required to build hyperchain, you can use command 'go version' to check your go compiler' version." >&2
    exit 2
}

# 判断要求的 Go 编译器版本与本地安装的 Go 编译版本一不一样
if [ "$CI_VERSION" == "$GO_VERSION" ]
then
    exit 0
else
    fail
fi