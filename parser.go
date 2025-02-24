package pkt_parser

/*
#include "parser.h"
*/
import "C"
import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"time"

	"github.com/pkg/errors"
	"github.com/segmentio/kafka-go"
)

var (
	writer    *kafka.Writer
	kafkaChan chan kafka.Message
)

// InitKafkaProducer 初始化 Kafka 生产者
func InitKafkaProducer(broker, topic string, kafkaBatchSize, bufferSize int) error {
	if broker == "" {
		return errors.New("kafka broker address is empty")
	}

	writer = &kafka.Writer{
		Addr:         kafka.TCP(broker),
		Balancer:     &kafka.LeastBytes{}, // 使用 LeastBytes 负载均衡策略
		Topic:        topic,
		Compression:  kafka.Snappy,   // 设置 Snappy 压缩
		BatchSize:    kafkaBatchSize, // 批量发送的消息数
		BatchTimeout: 100 * time.Millisecond,
		Async:        false, // 是否异步发送
	}

	kafkaChan = make(chan kafka.Message, bufferSize) // 缓冲队列，减少阻塞
	go kafkaWorker()                                 // 启动 Kafka 生产者
	log.Println("Kafka producer initialized successfully")
	return nil
}

// kafkaWorker 从缓冲队列中读取消息并发送到 Kafka
func kafkaWorker() {
	for msg := range kafkaChan {
		if err := writer.WriteMessages(context.Background(), msg); err != nil {
			slog.Error("Failed to send message to Kafka", "err", err)
		}
	}
}

// sendToKafka 生产者 将dpdk抓到的包解析后存储到kafka
func sendToKafka(key string, value []byte) error {
	if writer == nil {
		return errors.New("kafka producer is not initialized")
	}

	msg := kafka.Message{
		Key:   []byte(key),
		Value: value,
	}

	select {
	case kafkaChan <- msg: // 将消息放入缓冲队列
	default:
		slog.Warn("Kafka buffer is full, dropping packet")
	}

	return nil
}

// CloseKafkaProducer 关闭 Kafka 生产者
func CloseKafkaProducer() {
	close(kafkaChan) // 关闭通道
	if writer != nil {
		if err := writer.Close(); err != nil {
			slog.Error("Failed to close Kafka writer", "err", err)
		}
	}
	slog.Info("Kafka producer closed")
}

//export GetDataCallback
func GetDataCallback(data *C.char, length C.int, windowKey *C.char) {
	goPacket := ""
	if data != nil {
		goPacket = C.GoStringN(data, length)
	}

	// unmarshal each pkg dissect result
	frame, err := ParseFrameData(goPacket)
	if err != nil {
		slog.Warn("Error:", "ParseFrameData", err)
		if frame != nil {
			slog.Warn("Error:", "WsIndex", frame.Index)
		}
		return // 如果解析失败，直接返回，不继续处理
	}

	if frame == nil {
		slog.Warn("Error: ParseFrameData returned nil result")
		return
	}

	slog.Info("",
		"windowKey", C.GoString(windowKey),
		"proto", frame.BaseLayers.WsCol.Protocol,
		"src", frame.BaseLayers.WsCol.DefSrc,
		"dst", frame.BaseLayers.WsCol.DefDst,
		"info", frame.BaseLayers.WsCol.Info)

	// 将解析结果序列化为JSON或其他格式
	jsonData, err := json.Marshal(frame)
	if err != nil {
		slog.Warn("Error:", "json.Marshal", err)
		return
	}

	windowKeyStr := ""
	if windowKey != nil {
		windowKeyStr = C.GoString(windowKey)
	}

	// 发送到Kafka
	if err = sendToKafka(windowKeyStr, jsonData); err != nil {
		slog.Warn("Error: sendToKafka", "error", err)
	}
}

func StartParsePacket(ifName, kafkaAddr, groupID string) (err error) {
	// 回调函数
	C.setDataCallback((C.DataCallback)(C.GetDataCallback))

	if ifName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	errMsg := C.parse_packet(C.CString(ifName), C.CString(kafkaAddr), C.CString(groupID))
	if C.strlen(errMsg) != 0 {
		err = errors.Errorf("fail to capture packet live:%v", C.GoString(errMsg))
		return
	}

	return nil
}
