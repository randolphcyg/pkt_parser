package parser

/*
#cgo pkg-config: glib-2.0
#include "lib.h"
#include "parser.h"
*/
import "C"
import (
	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

var (
	ErrParseDissectRes = errors.New("fail to parse DissectRes")
)

// init initializes the Wireshark environment once on startup.
func init() {
	if !C.init_env() {
		panic("failed to initialize wireshark env")
	}
}

// ParseFrameData parses the JSON representation of a dissected frame.
func ParseFrameData(src []byte) (frame *FrameData, err error) {
	if len(src) == 0 {
		return nil, errors.New("empty input data")
	}

	err = sonic.Unmarshal(src, &frame)
	if err != nil {
		return nil, ErrParseDissectRes
	}

	var layerErrors []error
	parseLayer := func(layerFunc func() (any, error), setLayerFunc func(any)) {
		val, err := layerFunc()
		if err == nil {
			setLayerFunc(val)
		} else if !errors.Is(err, ErrLayerNotFound) {
			layerErrors = append(layerErrors, err)
		}
	}

	// Parse specific layers
	parseLayer(frame.Layers.WsCol, func(v any) { frame.BaseLayers.WsCol = v.(*WsCol) })
	parseLayer(frame.Layers.Frame, func(v any) { frame.BaseLayers.Frame = v.(*Frame) })
	parseLayer(frame.Layers.Eth, func(v any) { frame.BaseLayers.Eth = v.(*Eth) })
	parseLayer(frame.Layers.Ip, func(v any) { frame.BaseLayers.Ip = v.(*Ip) })
	parseLayer(frame.Layers.Udp, func(v any) { frame.BaseLayers.Udp = v.(*Udp) })
	parseLayer(frame.Layers.Tcp, func(v any) { frame.BaseLayers.Tcp = v.(*Tcp) })
	parseLayer(frame.Layers.Http, func(v any) { frame.BaseLayers.Http = v.([]*Http) })
	parseLayer(frame.Layers.Dns, func(v any) { frame.BaseLayers.Dns = v.(*Dns) })

	if len(layerErrors) > 0 {
		return frame, errors.Errorf("frame:%d errors:%v", frame.BaseLayers.Frame.Number, layerErrors)
	}

	return frame, nil
}
