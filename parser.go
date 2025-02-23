package pkt_parser

/*
#include "parser.h"
*/
import "C"
import (
	"encoding/json"
	"log/slog"

	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/pkg/errors"
)

const (
	produceChannelSize    = 1000
	messageSendMaxRetries = 3
	compressionCodec      = "snappy"
)

var P *kafka.Producer

// InitKafkaProducer 初始化 Kafka 生产者
func InitKafkaProducer(addr string) error {
	if addr == "" {
		return errors.New("kafka addr is empty")
	}

	config := &kafka.ConfigMap{
		"bootstrap.servers":        addr,
		"go.produce.channel.size":  produceChannelSize,
		"message.send.max.retries": messageSendMaxRetries,
		"compression.codec":        compressionCodec,
	}

	var err error
	P, err = kafka.NewProducer(config)
	if err != nil {
		return err
	}

	slog.Info("Kafka producer init successfully")
	return nil
}

func produceToKafka(topic string, key string, value []byte) error {
	msg := &kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
		Key:            []byte(key), // 使用时间窗口或其他唯一标识作为 Key
		Value:          value,       // 存储解析后的数据
	}

	deliveryChan := make(chan kafka.Event)
	defer close(deliveryChan)

	if err := P.Produce(msg, deliveryChan); err != nil {
		return err
	}

	e := <-deliveryChan
	m := e.(*kafka.Message)

	if m.TopicPartition.Error != nil {
		return m.TopicPartition.Error
	}

	return nil
}

//export GetDataCallback
func GetDataCallback(data *C.char, length C.int, interfaceName *C.char, windowKey *C.char) {
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
	if err := produceToKafka(C.GoString(interfaceName)+"_parsed_pkts", windowKeyStr, jsonData); err != nil {
		slog.Warn("Error: produceToKafka", "error", err)
	}
}

func StartParsePacket(interfaceName, kafkaAddr, groupID string) (err error) {
	// 回调函数
	C.setDataCallback((C.DataCallback)(C.GetDataCallback))

	if interfaceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	errMsg := C.parse_packet(C.CString(interfaceName), C.CString(kafkaAddr), C.CString(groupID))
	if C.strlen(errMsg) != 0 {
		err = errors.Errorf("fail to capture packet live:%v", C.GoString(errMsg))
		return
	}

	return nil
}
