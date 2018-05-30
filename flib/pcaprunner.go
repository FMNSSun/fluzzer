package flib

import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket"
import "os/exec"
//import "time"
import "net"

type RunnerContext struct {
	FuzzingContext *FuzzingContext
	Cmd *exec.Cmd
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

func RunPCAPPacketConn(addr net.Addr, pconn net.PacketConn, layerType gopacket.LayerType, in *pcap.Handle, out *pcap.Handle, ctx *RunnerContext) (bool, error) {
	cmd := ctx.Cmd
	
	waitCh := make(chan bool)

	go func() {
		if cmd != nil {
			cmd.Wait()
			waitCh <- true
		}
	}()

	packetSource := gopacket.NewPacketSource(in, in.LinkType())	

	for packet := range packetSource.Packets() {
		FuzzPacket(packet, ctx.FuzzingContext)

		data := serializePacketEx(layerType, packet)

		pconn.WriteTo(data, addr)

		select {
		case _ = <- waitCh:
			// process has terminated
			return true, nil
		default:
			// nop
		}
	}

	return false, nil
}

func RunPCAPCCmd(in *pcap.Handle, out *pcap.Handle, cmd *exec.Cmd, ctx *RunnerContext) (bool, error) {
	waitCh := make(chan bool)

	go func() {
		cmd.Wait()
		waitCh <- true
	}()

	packetSource := gopacket.NewPacketSource(in, in.LinkType())

	for packet := range packetSource.Packets() {
		FuzzPacket(packet, ctx.FuzzingContext)

		serLayers := getSerializableLayers(packet)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}

		gopacket.SerializeLayers(buf, opts, serLayers...)

		err := out.WritePacketData(buf.Bytes())

		if err != nil {
			return false, err
		}

		select {
		case _ = <- waitCh:
			// process has terminated
			return true, nil
		default:
			// nop
		}
		
	}

	return false, nil
}
