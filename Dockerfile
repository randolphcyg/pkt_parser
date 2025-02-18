# 第一阶段：构建阶段
FROM golang:1.24.0 AS builder

LABEL stage=gobuilder

ENV CGO_ENABLED=1
ENV GOPROXY=https://goproxy.cn,direct

# 安装构建所需的依赖库
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    libc-ares-dev \
    libgcrypt-dev \
    libglib2.0-dev \
    libpcap-dev \
    libxslt1-dev \
    pcaputils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /pkt_parser

# 复制 Go 依赖文件并下载依赖
COPY go.mod .
COPY go.sum .
RUN go mod download

# 复制全部代码
COPY . .

# 编译 Go + CGO 代码
RUN go build -ldflags="-s -w" -o /pkt_parser/pkt_parser ./cmd/main.go

# 第二阶段：运行时环境
FROM ubuntu:22.04

ENV TZ=Asia/Shanghai
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LANGUAGE=C.UTF-8
ENV LC_ALL=C.UTF-8

# 安装构建所需的依赖库
RUN sed -i s@/archive.ubuntu.com/@/cn.archive.ubuntu.com/@g /etc/apt/sources.list \
    && apt update \
    && apt -y dist-upgrade  \
    # 设置时区
    && apt install -y tzdata \
    && ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo ${TZ} > /etc/timezone \
    && dpkg-reconfigure --frontend noninteractive tzdata\
    && apt -y install build-essential \
    && apt -y install libc-ares-dev \
    && apt -y install libgcrypt-dev \
    && apt -y install libglib2.0-dev \
    && apt -y install libpcap-dev \
    && apt -y install libxslt1-dev \
    && apt -y install pcaputils && \
    rm -rf /var/lib/apt/lists/*


WORKDIR /app

# 复制编译后的二进制文件
COPY --from=builder /pkt_parser/pkt_parser /app/pkt_parser

# 复制额外的动态链接库
COPY --from=builder /pkt_parser/libs/lib*.so* /app/libs/

# 复制 CA 证书和时区信息
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo/Asia/Shanghai /usr/share/zoneinfo/Asia/Shanghai

# 设置环境变量
ENV LD_LIBRARY_PATH=/app/libs

# 设置工作目录
WORKDIR /app

# 启动抓包服务
ENTRYPOINT ["/app/pkt_parser"]