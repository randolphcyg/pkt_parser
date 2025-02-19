package pkt_parser

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark -lpcap -lrdkafka
#cgo CFLAGS: -I${SRCDIR}/include
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -I${SRCDIR}/include/libpcap
#cgo CFLAGS: -I${SRCDIR}/include/librdkafka
#include "lib.h"
#include "parser.h"
*/
import "C"
import (
	"encoding/json"
	"sync"

	"github.com/pkg/errors"
)

var (
	ErrParseDissectRes = errors.New("fail to parse DissectRes")
)

// Init policies、WTAP mod、EPAN mod.
func init() {
	success := C.init_env()
	if !success {
		panic("fail to init env")
	}
}

// ParseFrameData
//
// @Description: Unmarshal and prrocess frame data concurrently, including parsing multiple network layers.
// @param src: JSON string representing the frame data.
// @return frame: Parsed frame data.
func ParseFrameData(src string) (frame *FrameData, err error) {
	if src == "" {
		return nil, errors.New("empty input data")
	}

	err = json.Unmarshal([]byte(src), &frame)
	if err != nil {
		return nil, ErrParseDissectRes
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var layerErrors []error

	// parseAndSetLayer parses a network layer and sets the result in the frame data.
	parseAndSetLayer := func(layerFunc func() (any, error), setLayerFunc func(any)) {
		defer wg.Done()
		layer, err := layerFunc()
		if err != nil && !errors.Is(err, ErrLayerNotFound) { // ignore if layer not found
			layerErrors = append(layerErrors, err)
		}
		if layer != nil {
			mu.Lock()
			setLayerFunc(layer) // update BaseLayers
			mu.Unlock()
		}
	}

	wg.Add(7)

	go parseAndSetLayer(frame.Layers.WsCol, func(layer any) {
		frame.BaseLayers.WsCol = layer.(*WsCol)
	})

	go parseAndSetLayer(frame.Layers.Frame, func(layer any) {
		frame.BaseLayers.Frame = layer.(*Frame)
	})

	go parseAndSetLayer(frame.Layers.Ip, func(layer any) {
		frame.BaseLayers.Ip = layer.(*Ip)
	})

	go parseAndSetLayer(frame.Layers.Udp, func(layer any) {
		frame.BaseLayers.Udp = layer.(*Udp)
	})

	go parseAndSetLayer(frame.Layers.Tcp, func(layer any) {
		frame.BaseLayers.Tcp = layer.(*Tcp)
	})

	go parseAndSetLayer(frame.Layers.Http, func(layer any) {
		frame.BaseLayers.Http = layer.([]*Http)
	})

	go parseAndSetLayer(frame.Layers.Dns, func(layer any) {
		frame.BaseLayers.Dns = layer.(*Dns)
	})

	wg.Wait()

	// Summarize all errors of a frame
	if len(layerErrors) > 0 {
		return frame, errors.Errorf("frame:%d:%v", frame.BaseLayers.Frame.Number, layerErrors)
	}

	return frame, nil
}
