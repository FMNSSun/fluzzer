package flib

import "github.com/google/gopacket"
import "reflect"

type FuzzingContext struct {
	Fuzzers      []Fuzzer
	IgnoreErrors bool
}

func FuzzPacket(packet gopacket.Packet, ctx *FuzzingContext) error {
	// Iterate through fuzzers and invoke packet fuzzers if any
	for _, fuzzer := range ctx.Fuzzers {
		switch fuzzer.(type) {
		case PacketFuzzer:
			packetFuzzer := fuzzer.(PacketFuzzer)
			err := packetFuzzer.Func(packet)

			if err != nil && !ctx.IgnoreErrors {
				return err
			}
		}
	}

	// Iterate through layers
	packetLayers := packet.Layers()

	for _, layer := range packetLayers {
		layerName := gopacket.GetLayerTypeMetadata(int(layer.LayerType())).Name

		r := reflect.ValueOf(layer).Elem()

		if r.Type().Kind() == reflect.Slice {
			// don't want slices... just want structs (filters out the payload layer)
			continue
		}

		// Iterate over fuzzers and invoke them on their corresponding fields
		for _, fuzzer := range ctx.Fuzzers {
			switch fuzzer.(type) {
			case FieldFuzzer:
				fieldFuzzer := fuzzer.(FieldFuzzer)

				if fieldFuzzer.Layer == layerName {
					f := r.FieldByName(fieldFuzzer.Field)
					err := fieldFuzzer.Func(f)
					if err != nil && !ctx.IgnoreErrors {
						return err
					}
				}

			case LayerFuzzer:
				layerFuzzer := fuzzer.(LayerFuzzer)

				if layerFuzzer.Layer == layerName {
					err := layerFuzzer.Func(layer)

					if err != nil && !ctx.IgnoreErrors {
						return err
					}
				}
			}
		}
	}

	return nil
}
