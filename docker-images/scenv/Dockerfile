ARG UBUNTU_VER

FROM ubuntu:${UBUNTU_VER}

ARG GO_VER

RUN apt-get update && apt-get install -y \
    binutils-gold \
    curl \
    g++ \
    gcc \
    git

RUN curl -sL https://golang.google.cn/dl/go${GO_VER}.linux-amd64.tar.gz | tar zxvf - -C /usr/local
ENV PATH="$PATH:/usr/local/go/bin/"
RUN go env -w GOPROXY=https://goproxy.cn,direct

RUN addgroup --gid 500 smartcontract
RUN adduser --disabled-password --gecos "Xiangyu Wu,505,8612345678901,0551-1234567,other information (like i'm a student)" --uid 500 --gid 500 --home /home/smartcontract smartcontract

RUN mkdir -p /smartcontract/output /smartcontract/input

# 将 /smartcontract 目录及其子目录下的所有文件的所有者修改为 smartcontract/smartcontract
RUN chown -R smartcontract:smartcontract /smartcontract

USER smartcontract
