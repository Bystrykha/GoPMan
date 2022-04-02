package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"time"
)

func main() {
	printInterfaces()
	name := ""
	fmt.Scanln(&name)

	readTraffic(name, true)
}

func readTraffic(name string, print bool) int {
	var (
		deviceName  string = name
		snapshotLen int32  = 1024
		promiscuous bool   = false
		err         error
		timeout     time.Duration = 2 * time.Second
		handle      *pcap.Handle
	)
	packetCount := 0

	var w *pcapgo.Writer
	wait := 5 * time.Second
	if print {
		wait = 24 * time.Hour
		f, _ := os.Create("test.pcap")
		w = pcapgo.NewWriter(f)
		w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
		defer f.Close()
	}

	// Open the device for capturing
	handle, err = pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", deviceName, err)
		os.Exit(1)
	}
	defer handle.Close()

	start := time.Now()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for time.Since(start) <= wait {
		select {
		case packet, _ := <-packetSource.Packets():
			if print {
				fmt.Println(packet)
				w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			}

			packetCount++
		default:

		}
	}

	return packetCount

}

func printInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Devices found:")
	for _, device := range devices {
		go printInterface(device)
	}
}

func printInterface(p pcap.Interface) {
	n := readTraffic(p.Name, false)
	fmt.Println("\nName: ", p.Name)
	fmt.Println("Description: ", p.Description)
	fmt.Println("got ", n, "packets")
}
