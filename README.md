docker-compose部署
```shell
docker-compose up -d
docker-compose down
```

docker部署
```shell
docker pull golang:1.24.0 --platform linux/amd64
docker save -o golang-1.24.0.tar golang:1.24.0
docker load -i golang-1.24.0.tar


# 构建
sudo docker build --platform linux/amd64 -t pkt_parser:1.0 .
# 容器导出
sudo docker save pkt_parser:1.0  | gzip > pkt_parser_1_0.tar.gz
# 解压镜像
docker load -i pkt_parser_1_0.tar.gz

# 运行
docker run -d \
    --name pkt_parser \
    pkt_parser:1.0 \
    -i "ens33" -kafka "10.10.10.187:9092" -gid "packet_parser"
    
docker-compose up -d --scale pkt_parser=6
```