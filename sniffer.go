package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type filters struct {
	netProtocols   string
	transProtocols string
}

func sniffer() {
	printInterfaces()
	name := ""

	fmt.Print("Write name of interface: ")
	fmt.Scanln(&name)

	fmt.Print("Do you need filters? y/n - ")
	filter := filters{}
	t := ""
	fmt.Scanln(&t)
	switch t {
	case "y":
		fmt.Println("Starting with filters.")
		filter = createFilter()
	case "n":
		fmt.Println("Starting without filters.")

	default:
		fmt.Println("wrong answer. Starting without filters.")

	}
	_, err := readTraffic(name, true, filter)
	if err != nil {
		return
	}
}

func createFilter() filters {
	f := filters{"", " "}
	fmt.Println("Write network protocols:")
	fmt.Scanln(&f.netProtocols)
	fmt.Println("Write network protocols:")
	fmt.Scanln(&f.transProtocols)
	return f
}

func readTraffic(name string, print bool, filter filters) (int, error) {
	var (
		deviceName  string        = name
		snapshotLen int32         = 1024
		promiscuous bool          = false
		timeout     time.Duration = 10 * time.Millisecond
	)
	packetCount := 0

	var w *pcapgo.Writer
	wait := 5 * time.Second
	if print {
		wait = 24 * time.Hour
		f, _ := os.Create("test.pcap")
		w = pcapgo.NewWriter(f)
		err := w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
		if err != nil {
			return 0, err
		}
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				fmt.Println("error closing file ", err)
			}
		}(f)
	}

	// Open the device for capturing
	handle, err := pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
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
				if applyFilter(packet, filter) {
					fmt.Println(packet)
					err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
					if err != nil {
						return 0, err
					}
				}
			}

			packetCount++
		default:
		}
	}

	return packetCount, nil

}

func applyFilter(packet gopacket.Packet, filter filters) bool {

	if strings.Contains(strings.ToLower(filter.netProtocols),
		strings.ToLower(packet.Layers()[1].LayerType().String())) {
		if strings.Contains(strings.ToLower(filter.transProtocols),
			strings.ToLower(packet.Layers()[2].LayerType().String())) {
			return true
		}
	}

	return false
}

func printInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	fmt.Println("Scanning fo interfaces...")
	for _, device := range devices {
		wg.Add(1)
		go printInterface(device, &wg)
	}

	wg.Wait()
}

func printInterface(p pcap.Interface, wg *sync.WaitGroup) {
	n, _ := readTraffic(p.Name, false, filters{})

	if n != 0 {
		fmt.Println("Name: ", p.Name)
		fmt.Println("Description: ", p.Description)
		fmt.Print("got ", n, " packets per second\n\n")
	}

	wg.Done()
}
