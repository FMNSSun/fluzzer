package flib

import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket"
import "time"
import "net"

type RunnerContext struct {
	FuzzingContext   *FuzzingContext
	CmdWait          chan bool
	RepeatUntilCrash bool
	PacketLogger     func([]byte) error
	SendDelay        int
}

func getSerializableLayers(packet gopacket.Packet) []gopacket.SerializableLayer {
	packetLayers := packet.Layers()
	serLayers := make([]gopacket.SerializableLayer, len(packetLayers))

	for i, layer := range packetLayers {
		serLayers[i] = layer.(gopacket.SerializableLayer)
	}

	return serLayers
}

func getSerializableLayersEx(layerType gopacket.LayerType, packet gopacket.Packet) []gopacket.SerializableLayer {
	packetLayers := packet.Layers()
	serLayers := make([]gopacket.SerializableLayer, len(packetLayers))

	keep := false
	i := 0

	for _, layer := range packetLayers {
		if layer.LayerType() == layerType {
			keep = true
		}

		if !keep {
			continue
		}

		serLayers[i] = layer.(gopacket.SerializableLayer)
		i++
	}

	return serLayers[:i]
}

func serializePacket(packet gopacket.Packet) []byte {
	serLayers := getSerializableLayers(packet)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	gopacket.SerializeLayers(buf, opts, serLayers...)

	return buf.Bytes()
}

func serializePacketEx(layerType gopacket.LayerType, packet gopacket.Packet) []byte {
	serLayers := getSerializableLayersEx(layerType, packet)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	gopacket.SerializeLayers(buf, opts, serLayers...)

	return buf.Bytes()
}

func RunPCAPSimple(in *pcap.Handle, out *pcap.Handle, ctx *RunnerContext) error {
	packetSource := gopacket.NewPacketSource(in, in.LinkType())

	for packet := range packetSource.Packets() {
		FuzzPacket(packet, ctx.FuzzingContext)

		data := serializePacket(packet)

		err := out.WritePacketData(data)

		if err != nil {
			return err
		}
	}

	return nil
}

func RunPacketConn(packetSource *gopacket.PacketSource, addr net.Addr, pconn net.PacketConn, layerType gopacket.LayerType, ctx *RunnerContext) (bool, error) {

	for packet := range packetSource.Packets() {
		FuzzPacket(packet, ctx.FuzzingContext)

		data := serializePacketEx(layerType, packet)

		_, err := pconn.WriteTo(data, addr)

		if err != nil {
			return false, err
		}

		if ctx.PacketLogger != nil {
			ctx.PacketLogger(data)
		}

		if ctx.SendDelay > 0 {
			time.Sleep(time.Duration(ctx.SendDelay) * time.Millisecond)
		}

		select {
		case _ = <-ctx.CmdWait:
			// process has terminated
			return true, nil
		default:
			// nop
		}

	}

	return false, nil
}

func Run(packetSource *gopacket.PacketSource, out *pcap.Handle, ctx *RunnerContext) (bool, error) {

	for packet := range packetSource.Packets() {
		FuzzPacket(packet, ctx.FuzzingContext)

		serLayers := getSerializableLayers(packet)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}

		gopacket.SerializeLayers(buf, opts, serLayers...)
		data := buf.Bytes()

		err := out.WritePacketData(data)

		if err != nil {
			return false, nil
		}

		if ctx.PacketLogger != nil {
			ctx.PacketLogger(data)
		}

		if ctx.SendDelay > 0 {
			time.Sleep(time.Duration(ctx.SendDelay) * time.Millisecond)
		}

		select {
		case _ = <-ctx.CmdWait:
			// process has terminated
			return true, nil
		default:
			// nop
		}

	}

	return false, nil
}
