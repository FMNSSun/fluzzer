package main

//import "github.com/google/gopacket"
import "github.com/google/gopacket/layers"
import "github.com/FMNSSun/fluzzer/flib"

//import "fmt"
import "flag"

//import "encoding/json"

var run string = "/home/mroman/go/src/github.com/FMNSSun/rndcrash/rndcrash"
var args []string = []string{}
var iface string = "lo"
var laddr string = "127.0.0.1:5000"
var raddr string = "127.0.0.1:8888"
var path string = "/home/mroman/MAMI/plus.pcap"

func main() {
	flag.Parse()
	layers.EnableHeuristics()

	runnerContext := &flib.RunnerContext{
		SendDelay: 0,
		PacketLogger: func(data []byte) error {
			//fmt.Printf("data: %x\n", data)
			return nil
		},
		FuzzingContext: &flib.FuzzingContext{
			Fuzzers: []flib.Fuzzer{
				flib.FieldFuzzer{
					Layer: "PLUS",
					Field: "PSN",
					Func:  flib.RndUint32,
				},
			},
		},
	}

	flib.FuzzPacketConnPCAP(path, run, args, laddr, raddr, runnerContext)
}
