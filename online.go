package pkt_parser

/*
#cgo pkg-config: glib-2.0
#cgo CFLAGS: -I${SRCDIR}/include
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -I${SRCDIR}/include/libpcap
#cgo CFLAGS: -I${SRCDIR}/include/librdkafka

#include "lib.h"
#include "online.h"
#include "offline.h"
*/
import "C"
import (
	"encoding/json"
	"log/slog"

	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/pkg/errors"
)

var P *kafka.Producer

// InitKafkaProducer 初始化 Kafka 生产者
func InitKafkaProducer(addr string) error {
	if addr == "" {
		return errors.New("kafka addr is empty")
	}

	var err error
	P, err = kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": addr})
	if err != nil {
		return err
	}

	slog.Info("Kafka producer init successfully")
	return nil
}

func produceToKafka(topic string, key string, value []byte) {
	msg := &kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
		Key:            []byte(key), // 使用时间窗口或其他唯一标识作为 Key
		Value:          value,       // 存储解析后的数据
	}

	if err := P.Produce(msg, nil); err != nil {
		slog.Info("Failed to send message: %s", err)
	}
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
	produceToKafka(C.GoString(interfaceName)+"_parsed_pkts", windowKeyStr, jsonData)
}

func StartParsePacket(interfaceName, kafkaAddr string, opts ...Option) (err error) {
	// Set up callback function
	C.setDataCallback((C.DataCallback)(C.GetDataCallback))

	if interfaceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	conf := NewConfig(opts...)

	errMsg := C.parse_packet(C.CString(interfaceName), C.CString(kafkaAddr), C.CString(HandleConf(conf)))
	if C.strlen(errMsg) != 0 {
		errMsgStr := C.GoString(errMsg) // 转换为 Go 字符串
		err = errors.Errorf("fail to capture packet live:%s", errMsgStr)
		return
	}

	return
}
