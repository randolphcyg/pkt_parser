# pkt_parser - Wireshark 协议解析服务

`pkt_parser` 是一个高性能的协议解析组件。它作为 Kafka Consumer 运行，消费由 DPDK 捕获的原始网络包，利用 `libwireshark` 引擎进行深度协议分析（Dissection），并将解析后的 JSON 结果写回 Kafka。

------

## 🏗 架构说明

```mermaid
graph LR
    Capturer[DPDK Capturer] -->|Raw Bytes| Kafka[Kafka Raw Topic]
    Kafka -->|Consume| C_Consumer[C Consumer]
    C_Consumer -->|Packet| Wireshark[Libwireshark Dissector]
    Wireshark -->|JSON| Go_Callback[Go Callback]
    Go_Callback -->|Produce| Kafka_Parsed[Kafka Parsed Topic]
```

- 输入: Kafka Topic (原始二进制 pcap 数据帧)
- 处理: CGO 调用 libwireshark 进行协议树还原
- 输出: Kafka Topic (JSON 格式的协议详情)

## 🚀 部署指南

### 1. 构建
```shell
docker build -t pkt_parser:latest . --platform linux/amd64
# 容器导出
docker save pkt_parser:latest  | gzip > pkt_parser.tar.gz
# 解压镜像
docker load -i pkt_parser.tar.gz
```

### 2. 运行
```shell
docker run -d \
    --name pkt_parser \
    pkt_parser:latest \
    -deviceID "win_dev_01" \
    -sourceTopic "eth0_capture" \
    -sinkTopic "parsed_data" \
    -kafka "192.168.11.82:9092" \
    -gid "packet_parser_group_01" \
    -batchSize 200 \
    -bufferSize 2000
    
docker-compose up -d --scale pkt_parser=6
```
注意: 建议使用 --net=host 以获得最佳网络性能，特别是与 Kafka 通信频繁时。

### 3. Docker Compose 集群模式

通过 Scale 扩展实例数量以提高消费吞吐量。

```shell
docker-compose up -d
docker-compose down
```

## ⚙️ 参数说明

| **参数**         | **默认值**         | **说明**                                              |
|----------------|-----------------|-----------------------------------------------------|
| `-deviceID`    | `eth0`          | 逻辑ID 用于内存索引、日志标记及监控统计的 Key                          |
| `-sourceTopic` | `eth0`          | 数据源 Kafka 中存放原始二进制包的 Topic（通常由 Capturer 产生）         |
| `-sinkTopic`   | `parsed_pkts`   | 落地目标 解析后的 JSON 数据发送到的 Kafka Topic                   |
| `-kafka`       | `...`           | Kafka Broker 地址列表                                   |
| `-gid`         | `packet_parser` | **消费者组 ID**。多实例部署时必须相同，以利用 Kafka 的 Rebalance 机制分摊流量 |
| `-batchSize`   | `100`           | Kafka 生产者批量发送的消息条数                                  |
| `-bufferSize`  | `1000`          | 内部 Go Channel 缓冲队列长度                                |

------

## 📊 性能与调试 (Performance & Debugging)

本服务内置了多维度的监控机制，旨在帮助运维人员快速定位 **解析瓶颈**（CPU限制）与 **下游积压**（Kafka限制）。

### 1. 实时性能日志

服务启动后，主程序会启动一个独立协程，每隔 **5秒** 打印一次性能快照。

**日志示例 (Text 格式):**

```
2026/01/21 17:05:32 INFO Performance in_pps=48500 out_pps=48500 mbps=412.50 queue_len=120 drop_total=0 drop_rate=0
2026/01/21 17:05:37 INFO Performance in_pps=52100 out_pps=51950 mbps=445.10 queue_len=250 drop_total=0 drop_rate=0
2026/01/21 17:05:42 INFO Performance in_pps=61000 out_pps=45000 mbps=510.20 queue_len=2000 drop_total=1500 drop_rate=300
```

*(注：最后一行显示出现了阻塞和丢包)*

**指标详解：**

| **指标字段**       | **含义**                                              | **🔴 异常判断阈值**                                                                               |
|----------------|-----------------------------------------------------|---------------------------------------------------------------------------------------------|
| **in_pps**     | **解析速率** (包/秒)。从 C 端 Wireshark 解析引擎接收到的数据包数量。       | 若远低于上游抓包服务的发送速率，说明 **CPU 算力不足**，解析太慢。                                                       |
| **out_pps**    | **发送速率** (条/秒)。成功写入 Kafka 发送缓冲区的消息数量。               | 理想情况应 ≈ `in_pps`。若持续低于 `in_pps`，会导致队列积压。                                                    |
| **mbps**       | **处理带宽** (Mbps)。解析出的 JSON 数据流量大小。                   | 取决于协议解析深度和包大小。                                                                              |
| **queue_len**  | **内部积压**。Go Channel 缓冲队列的当前长度 (Max = `bufferSize`)。 | • **健康**: `< 10% bufferSize` • **警告**: `> 50%` (Kafka 写入变慢) • **阻塞**: `≈ bufferSize` (即将丢包) |
| **drop_total** | **累计丢包**。因队列满而丢弃的数据包总数。                             | 应始终为 0。                                                                                     |
| **drop_rate**  | **丢包速率** (条/秒)。最近 5 秒内的丢包速度。                        | **> 0 即需告警**。                                                                               |

------

### 2. 深度剖析 (Pprof)

服务默认监听 `:6060` 端口，提供 Go 标准 Pprof 调试接口。

- **访问地址**: `http://<容器IP>:6060/debug/pprof/`
- **常用分析命令**:

Bash

```
# 1. 分析 CPU 热点 (查找 Wireshark 解析中最耗时的协议层)
go tool pprof -http=:8080 http://localhost:6060/debug/pprof/profile?seconds=30

# 2. 分析内存占用 (排查 CGO 内存泄漏或大对象分配)
go tool pprof -http=:8080 http://localhost:6060/debug/pprof/heap

# 3. 查看协程阻塞 (排查 Kafka 发送死锁)
go tool pprof -http=:8080 http://localhost:6060/debug/pprof/goroutine
```

------

### 3. 常见问题调优 (Troubleshooting)

#### 场景 A：日志出现 `drop_rate > 0` 且 `queue_len` 爆满

- **原因**: 解析速度快于 Kafka 发送速度，导致 Go Channel 堵塞。通常是因为 Kafka Broker 响应慢或网络带宽打满。
- **解决方案**:
    1. **调大 Batch**: 启动参数 `-batchSize 500` 或更高（牺牲延迟换吞吐）。
    2. **调大 Buffer**: 启动参数 `-bufferSize 5000`（抗抖动）。
    3. **扩容 Kafka**: 增加 Topic 分区数。

#### 场景 B：`in_pps` 很低，且 CPU 占用率 100%

- **原因**: Wireshark 解析逻辑是计算密集型任务，单核算力达到瓶颈。
- **解决方案**:
    1. **横向扩容 (Scale Out)**: 这是最有效的方案。在 Docker Compose 中增加实例数：`replicas: 4`。
    2. **确保 Group ID 一致**: 所有实例必须使用相同的 `-gid`，以便 Kafka 自动进行负载均衡。

#### 场景 C：服务运行一段时间后 OOM (内存溢出)

- **原因**: 可能是 CGO 层的内存泄漏（如未释放的 `g_string` 或 Kafka message）。
- **排查**: 使用 `pprof/heap` 对比运行 1 小时和 24 小时后的内存快照。

## TODO

当前libwireshark解析有bug，需要解决。