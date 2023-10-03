# 该 Makefile 文件定义了以下功能：
#
#	- check-go-version: 检查 Go 编译器的版本号是否对应的上


###########################################################
######################### 定义变量 #########################
###########################################################

# 定义采用的 Ubuntu 的版本号
UBUNTU_VER ?= 20.04
# 定义 hyperchain 的版本号
HYPERCHAIN_VER ?= 1.0.0
# 定义 Go 编译器的版本
GO_VER ?= 1.20.7
# 定义构建项目的输出地址
BUILD_DIR ?= build
# 定义构建的镜像名字
RELEASE_IMAGES = baseos
# 定义构建项目的平台类型
RELEASE_PLATFORMS = linux-amd64
# 获取电脑处理器架构
ARCH=$(shell go env GOARCH)


###########################################################
######################### 定义功能 #########################
###########################################################

# 检查 Go 本地安装的编译器版本是否与指定的版本一致
.PHONY: check-go-version
check-go-version:
	@scripts/check_go_version.sh ${GO_VER}

.PHONY: docker
docker: build-docker-image-baseos build-docker-image-scenv

# 构建基本操作系统
build-docker-image-baseos:
	@echo "Building docker image 11090815/hyperchain-baseos"
	@docker build --force-rm -f docker-images/baseos/Dockerfile \
		--build-arg UBUNTU_VER=${UBUNTU_VER} \
		-t 11090815/hyperchain-baseos:${HYPERCHAIN_VER} ./docker-images/baseos

# 构建智能合约运行环境的镜像
build-docker-image-scenv:
	@echo "Building docker image 11090815/hyperchain-scenv"
	@docker build --force-rm -f docker-images/scenv/Dockerfile \
		--build-arg GO_VER=${GO_VER} \
		--build-arg UBUNTU_VER=${UBUNTU_VER} \
		-t 11090815/hyperchain-scenv:${HYPERCHAIN_VER} ./docker-images/scenv


###########################################################
######################### 测试功能 #########################
###########################################################

.PHONY: print
print:
	@echo $(UBUNTU_VER)

.PHONY: test
test: test1 test2

.PHONY: test1
test1:
	@echo "test1"

.PHONY: test2
test2:
	@echo "test2"



# 下面是一些 Makefile 的语法知识点
#
#	- ?= 符号：问号加等号的作用是，如果没有被赋值过就赋予等号后面的值