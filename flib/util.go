package flib

import "os"
import "os/exec"
import "net"
import "github.com/google/gopacket/pcap"
import "github.com/google/gopacket/layers"

func FuzzPacketConnPCAP(path string, run string, args []string, laddr string, raddr string, ctx *RunnerContext) error {
	cmd := exec.Command(run, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	
	if err != nil {
		panic(err.Error())
	}

	waitCh := make(chan bool)

	go func() {
		if cmd != nil {
			cmd.Wait()
			waitCh <- true
		}
	}()

	ctx.CmdWait = waitCh

	packetConn, err := net.ListenPacket("udp", laddr)
	udpAddr, err := net.ResolveUDPAddr("udp", raddr)

	for {
		in, err := pcap.OpenOffline(path)

		if err != nil {
			return err
		}

		crashed, err := RunPCAPPacketConn(udpAddr, packetConn, layers.LayerTypePLUS, in, ctx)
		in.Close()

		if err != nil {
			return err
		}

		if crashed {
			break
		}
	}

	err = cmd.Process.Kill()

	if err != nil {
		return err
	}

	return nil
}
