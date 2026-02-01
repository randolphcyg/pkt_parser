package parser

/*
#include "parser.h"
*/
import "C"
import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
	"github.com/segmentio/kafka-go"
)

var (
	writer    *kafka.Writer
	kafkaChan chan kafka.Message
	wg        sync.WaitGroup
)

// 全局统计计数器 (使用原子操作)
var (
	StatsRxPackets  uint64 // 接收到的解析包数
	StatsRxBytes    uint64 // 接收到的字节数 (JSON大小)
	StatsTxPackets  uint64 // 放入发送队列数
	StatsDropQueue  uint64 // 队列满丢弃数
	StatsParseError uint64 // 解析错误数
)

// ParserStats 统计快照
type ParserStats struct {
	RxPackets   uint64
	RxBytes     uint64
	TxPackets   uint64
	Dropped     uint64
	ParseErrors uint64
	QueueLen    int
}

func GetStats() ParserStats {
	return ParserStats{
		RxPackets:   atomic.LoadUint64(&StatsRxPackets),
		RxBytes:     atomic.LoadUint64(&StatsRxBytes),
		TxPackets:   atomic.LoadUint64(&StatsTxPackets),
		Dropped:     atomic.LoadUint64(&StatsDropQueue),
		ParseErrors: atomic.LoadUint64(&StatsParseError),
		QueueLen:    len(kafkaChan), // Channel 长度是线程安全的
	}
}

// InitKafkaProducer 初始化 Kafka 生产者
func InitKafkaProducer(broker, sinkTopic string, kafkaBatchSize, bufferSize int) error {
	if broker == "" {
		return errors.New("kafka broker address is empty")
	}

	writer = &kafka.Writer{
		Addr:         kafka.TCP(broker),
		Balancer:     &kafka.LeastBytes{}, // 使用 LeastBytes 负载均衡策略
		Topic:        sinkTopic,
		Compression:  kafka.Snappy,   // 设置 Snappy 压缩
		BatchSize:    kafkaBatchSize, // 批量发送的消息数
		BatchBytes:   10485760,       // 10MB
		BatchTimeout: 10 * time.Millisecond,
		Async:        false, // 是否异步发送
	}

	kafkaChan = make(chan kafka.Message, bufferSize) // 缓冲队列，减少阻塞

	wg.Add(1)
	go kafkaWorker()
	slog.Info("Kafka producer initialized successfully")
	return nil
}

// kafkaWorker 从缓冲队列中读取消息并发送到 Kafka
func kafkaWorker() {
	defer wg.Done()
	// 当 channel 被 close 且数据读完后，循环会自动结束
	for msg := range kafkaChan {
		if err := writer.WriteMessages(context.Background(), msg); err != nil {
			// [TODO] 使用采样日志，防止 Kafka 挂掉时日志爆炸
			//slog.Error("Failed to send message to Kafka", "err", err)
		}
	}
}

// sendToKafka 生产者 将dpdk抓到的包解析后存储到kafka
func sendToKafka(key []byte, value []byte) error {
	msg := kafka.Message{
		Key:   key,
		Value: value,
	}

	select {
	case kafkaChan <- msg: // 将消息放入缓冲队列
		atomic.AddUint64(&StatsTxPackets, 1)
	default:
		atomic.AddUint64(&StatsDropQueue, 1)
	}

	return nil
}

// CloseKafkaProducer 关闭 Kafka 生产者
func CloseKafkaProducer() {
	if kafkaChan != nil {
		close(kafkaChan) // 1. 停止接收新数据
	}

	wg.Wait() // 2. 等待 Worker 处理完剩余数据

	if writer != nil {
		if err := writer.Close(); err != nil { // 3. 安全关闭连接
			slog.Error("Failed to close Kafka writer", "err", err)
		}
	}
	slog.Info("Kafka producer closed")
}

//export GetDataCallback
func GetDataCallback(data *C.char, length C.int, windowKey *C.char) {
	if data == nil || length <= 0 {
		return
	}

	atomic.AddUint64(&StatsRxPackets, 1)
	atomic.AddUint64(&StatsRxBytes, uint64(length))

	goPacket := C.GoBytes(unsafe.Pointer(data), length)

	frame, err := ParseFrameData(goPacket)
	if err != nil {
		// 仅在 Debug 级别记录解析错误，或者采样记录
		return
	}
	if frame == nil {
		return
	}

	jsonData, err := sonic.Marshal(frame)
	if err != nil {
		return
	}

	var keyBytes []byte
	if windowKey != nil {
		keyBytes = []byte(C.GoString(windowKey))
	}

	// 发送到 Kafka
	sendToKafka(keyBytes, jsonData)
}

func StopParsePacket() {
	C.stop_parser_loop()
}

func StartParsePacket(ifName, sourceTopic, kafkaAddr, groupID string) (err error) {
	cIfName := C.CString(ifName)
	cSource := C.CString(sourceTopic)
	cAddr := C.CString(kafkaAddr)
	cGroup := C.CString(groupID)
	defer func() {
		C.free(unsafe.Pointer(cIfName))
		C.free(unsafe.Pointer(cSource))
		C.free(unsafe.Pointer(cAddr))
		C.free(unsafe.Pointer(cGroup))
	}()

	C.setDataCallback((C.DataCallback)(C.GetDataCallback))
	errMsg := C.parse_packet(cIfName, cSource, cAddr, cGroup)
	if C.strlen(errMsg) != 0 {
		err = errors.Errorf("fail to capture packet live:%v", C.GoString(errMsg))
		return
	}

	return nil
}
