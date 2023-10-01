ARG GO_VER
ARG UBUNTU_VER

FROM ubuntu:${UBUNTU_VER} as base

RUN apt-get update $$ apt-get install -y \
    # 安装时区数据库
    tzdata 

# 创建一个用户组，其 group id 是 500
# 在 /etc/group 文件的最后一行添加了一条新增的组信息：chaincode:x:500:
RUN addgroup --gid 500 chaincode

# 创建一个用户 chaincode，并将其关联到 chaincode 组，--gecos 用来标识输入的 chaincode 的指纹信息，用逗号隔开：①姓名 ②房号 ③手机号 ④家庭电话 ⑤其他信息
# 此条命令在 /etc/passwd 文件的最后一行添加了一条新增的用户信息：chaincode:x:500:500:Xiangyu Wu,505,8612345678901,0551-1234567,other information (like i'm a student):/home/chaincode:/bin/bash
RUN adduser --disabled-password --gecos "Xiangyu Wu,505,8612345678901,0551-1234567,other information (like i'm a student)" --uid 500 --gid 500 --home /home/chaincode chaincode

# 切换到 chaincode 用户，将来通过该镜像生成的容器在执行命令时，都将由 chaincode 用户负责执行
USER chaincode