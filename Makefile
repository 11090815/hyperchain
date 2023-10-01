# 下面是一些 Makefile 的语法知识点
#
#	- ?= - 问号加等号的作用是，如果没有被赋值过就赋予等号后面的值

# 定义采用的 Ubuntu 的版本号
UBUNTU_VER ?= 22.04
# 定义 hyperchain 的版本号
HYPERCHAIN_VER ?= 2.0.0
# 定义构建项目的输出地址
BUILD_DIR ?= build

# 定义拉取或者构建的镜像名字
RELEASE_IMAGES = baseos



.PHONY: print

print:
	@echo $(UBUNTU_VER)