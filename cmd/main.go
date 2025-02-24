package main

import "C"
import (
	"context"
	"flag"
	"log/slog"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"pkt_parser"
)

const TopicSuffix = "_parsed_pkts"

var ifName = flag.String("i", "ens33", "interface name")
var groupID = flag.String("gid", "packet_parser", "group id")
var kafkaAddr = flag.String("kafka", "10.10.10.187:9092", "kafka address")
var kafkaBatchSize = flag.Int("batchSize", 100, "kafka 批量发送大小")
var bufferSize = flag.Int("bufferSize", 1000, "缓冲队列大小")

// waitForShutdown 等待退出信号
func waitForShutdown(ctx context.Context) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		slog.Info("Received shutdown signal, shutting down...")
	case <-ctx.Done():
		slog.Info("Context canceled, shutting down...")
	}
}

func main() {
	flag.Parse()

	// 创建上下文，用于优雅退出
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置 Kafka 地址并初始化 Kafka 生产者
	topic := *ifName + TopicSuffix
	if err := pkt_parser.InitKafkaProducer(*kafkaAddr, topic, *kafkaBatchSize, *bufferSize); err != nil {
		slog.Error("Failed to initialize Kafka producer: %v", err)
		return
	}

	// 关闭 Kafka 生产者
	defer pkt_parser.CloseKafkaProducer()

	// 启动包解析服务
	err := pkt_parser.StartParsePacket(*ifName, *kafkaAddr, *groupID)
	if err != nil {
		slog.Error("Failed to start packet parser: %v", err)
	}

	// 等待退出信号
	waitForShutdown(ctx)

	slog.Info("Packet parser stopped, exiting...")
}
