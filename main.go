package main

import "github.com/google/gopacket/pcap"
//import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "github.com/FMNSSun/fluzzer/flib"
import "fmt"
import "flag"
//import "encoding/json"
import "time"
import "net"
import "os/exec"

var path = flag.String("pcap-file", "", "Path to a PCAP file.")
var iface = flag.String("iface", "lo", "Interface for outbound packets.")
var cmd = flag.String("cmd", "", "Command to run.")
var laddr = flag.String("laddr", "127.0.0.1:5000", "Local address.")
var raddr = flag.String("raddr", "127.0.0.1:8888", "Target address.")

func main() {
	flag.Parse()
	layers.EnableHeuristics()

	runnerContext := &flib.RunnerContext {
		FuzzingContext : &flib.FuzzingContext {
			Fuzzers : []flib.Fuzzer {
				flib.FieldFuzzer {
					Layer : "PLUS",
					Field : "PSN",
					Func : flib.RndUint32,
				},
			},
		},
	}

	in, err := pcap.OpenOffline(*path)

	if err != nil {
		panic(err)
	}

	out , err := pcap.OpenLive(*iface, 65535, true, -1 * time.Second)

	if err != nil {
		panic(err)
	}

	packetConn, err := net.ListenPacket("udp", *laddr)
	udpAddr, err := net.ResolveUDPAddr("udp4", *raddr)

	cmd := exec.Command("netcat","-ul","8888")
	err = cmd.Start()
	
	if err != nil {
		fmt.Println(err.Error())
	}

	runnerContext.Cmd = cmd

	crashed, err := flib.RunPCAPPacketConn(udpAddr, packetConn, layers.LayerTypePLUS, in, out, runnerContext)

	fmt.Println("crashed? ", crashed)
}
