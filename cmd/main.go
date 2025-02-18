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

var ifName = flag.String("i", "ens33", "interface name")
var kafkaAddr = flag.String("kafka", "192.168.3.93:9092", "kafka address")

func main() {
	flag.Parse()

	// 创建上下文，用于优雅退出
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 设置 Kafka 地址并初始化 Kafka 生产者
	addr := kafkaAddr
	if err := pkt_parser.InitKafkaProducer(*addr); err != nil {
		slog.Error("Failed to initialize Kafka producer: %v", err)
		return
	}

	err := pkt_parser.StartParsePacket(*ifName, *addr, pkt_parser.PrintCJson(false))
	if err != nil {
		slog.Error("Failed to start packet parser: %v", err)
	}

	// 等待退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 阻塞，直到接收到退出信号
	select {
	case <-sigChan:
		slog.Info("Received shutdown signal, shutting down...")
	case <-ctx.Done():
		slog.Info("Context canceled, shutting down...")
	}

	// 关闭 Kafka 生产者
	pkt_parser.P.Close()

	slog.Info("Packet parser stopped, exiting...")
}
