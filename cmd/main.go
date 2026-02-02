package main

import "C"
import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pkt_parser/pkg/parser"
)

var deviceID = flag.String("deviceID", "eth0", "逻辑设备名")
var sourceTopic = flag.String("sourceTopic", "eth0", "要消费的原始数据 Topic")
var sinkTopic = flag.String("sinkTopic", "parsed_pkts", "输出的 Topic")
var groupID = flag.String("gid", "packet_parser", "group id")
var kafkaAddr = flag.String("kafka", "10.10.10.187:9092", "kafka address")
var kafkaBatchSize = flag.Int("batchSize", 100, "kafka 批量发送大小")
var bufferSize = flag.Int("bufferSize", 1000, "缓冲队列大小")

func main() {
	flag.Parse()

	// 初始化日志 (可选：设置为 JSON 格式以便于收集)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// 1. 启动 Pprof 性能监控 (独立 Goroutine)
	go func() {
		pprofAddr := ":6060"
		slog.Info("Starting pprof server", "addr", pprofAddr)
		if err := http.ListenAndServe(pprofAddr, nil); err != nil {
			slog.Error("Pprof server failed", "err", err)
		}
	}()

	// 创建上下文，用于全局控制退出
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. 初始化 Kafka 生产者
	if err := parser.InitKafkaProducer(*kafkaAddr, *sinkTopic, *kafkaBatchSize, *bufferSize); err != nil {
		slog.Error("Failed to initialize Kafka producer", "err", err)
		os.Exit(1)
	}

	// 确保 Kafka 在主函数退出时关闭
	defer parser.CloseKafkaProducer()

	// 3. 启动监控
	go monitorMetrics(ctx)

	// 4. 启动包解析服务
	if *sourceTopic == "" {
		*sourceTopic = *deviceID
	}
	go func() {
		slog.Info("Starting packet parser", "sourceTopic", *sourceTopic, "sinkTopic", *sinkTopic, "interface", *deviceID, "kafka", *kafkaAddr)

		// 如果 C 代码是阻塞的，这里会一直运行
		err := parser.StartParsePacket(*deviceID, *sourceTopic, *kafkaAddr, *groupID)
		if err != nil {
			slog.Error("Packet parser failed or stopped unexpectedly", "err", err)
			cancel() // 若解析器挂了，取消 Context，通知主线程退出
		}
	}()

	// 5. 等待退出信号
	waitForShutdown(ctx)
}

func monitorMetrics(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastStats parser.Stats
	lastTime := time.Now()

	slog.Info("Metrics monitor started")

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			currentStats := parser.GetStats()
			timeDiff := now.Sub(lastTime).Seconds()

			if timeDiff <= 0 {
				continue
			}

			// 计算速率 (Delta / Time)
			rxDiff := float64(currentStats.RxPackets - lastStats.RxPackets)
			txDiff := float64(currentStats.TxPackets - lastStats.TxPackets)
			byteDiff := float64(currentStats.RxBytes - lastStats.RxBytes)
			dropDiff := float64(currentStats.Dropped - lastStats.Dropped)

			pps := rxDiff / timeDiff
			outPps := txDiff / timeDiff
			mbps := (byteDiff * 8) / 1000000.0 / timeDiff

			slog.Info("Performance",
				"in_pps", int(pps), // 解析输入速率 (包/秒)
				"out_pps", int(outPps), // Kafka 发送速率
				"mbps", fmt.Sprintf("%.2f", mbps), // 处理带宽
				"queue_len", currentStats.QueueLen, // 内部 Channel 积压
				"drop_total", currentStats.Dropped, // 总丢包
				"drop_rate", int(dropDiff/timeDiff), // 丢包速率
			)

			lastStats = currentStats
			lastTime = now
		}
	}
}

// waitForShutdown 等待退出信号或 Context 取消
func waitForShutdown(ctx context.Context) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		slog.Info("Received shutdown signal", "signal", sig.String())
	case <-ctx.Done():
		slog.Info("Context canceled")
	}

	slog.Info("Stopping C parser loop...")
	parser.StopParsePacket()
	// 在这里添加一个短暂的超时，给 defer 的资源清理留出时间
	// 实际清理逻辑在 main 的 defer 中执行
	time.Sleep(1 * time.Second)
}
