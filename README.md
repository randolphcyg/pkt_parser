
```shell
docker pull golang:1.24.0 --platform linux/amd64
docker save -o golang-1.24.0.tar golang:1.24.0
docker load -i golang-1.24.0.tar


# 构建
sudo docker build --platform linux/amd64 -t pkt_parser:1.0 .

sudo docker build -t pkt_parser:1.0 .

# 容器导出
sudo docker save pkt_parser:1.0  | gzip > pkt_parser_1_0.tar.gz
# 解压镜像
docker load -i pkt_parser_1_0.tar.gz

# 运行
docker run --rm -it \
    pkt_parser:1.0 -- \
    -i "ens66" -kafka "192.168.3.93:9092"
```