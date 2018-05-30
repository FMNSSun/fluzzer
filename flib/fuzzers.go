package flib

import "reflect"
import "github.com/google/gopacket"

const FIELD_FUZZER = uint8(0)
const LAYER_FUZZER = uint8(1)
const PACKET_FUZZER = uint8(2)

type Fuzzer interface {
	FuzzerType() uint8
}

type FieldFuzzer struct {
	Layer string
	Field string
	Func  func(v reflect.Value) error
}

func (_ FieldFuzzer) FuzzerType() uint8 {
	return FIELD_FUZZER
}

type LayerFuzzer struct {
	Layer string
	Func  func(layer gopacket.Layer) error
}

func (_ LayerFuzzer) FuzzerType() uint8 {
	return LAYER_FUZZER
}

type PacketFuzzer struct {
	Func func(packet gopacket.Packet) error
}

func (_ PacketFuzzer) FuzzerType() uint8 {
	return PACKET_FUZZER
}
