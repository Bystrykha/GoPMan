package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"sync"
	"time"
)

type filters struct {
}

func sniffer() {
	printInterfaces()
	name := ""
	//time.Sleep(5 * time.Second)
	fmt.Print("Write name of interface: ")
	fmt.Scanln(&name)

	fmt.Println("Do you need filters? y/n")
	filter := ""
	fmt.Scanln(&filter)
	switch filter {
	case "y":
		fmt.Println("Write filter string:")
		fmt.Scanln(&filter)
	case "n":
		fmt.Println("Starting without filters.")
		filter = ""
	default:
		fmt.Println("wrong answer. Starting without filters.")
		filter = ""
	}
	_, err := readTraffic(name, true, filter)
	if err != nil {
		return
	}
}

func readTraffic(name string, print bool, filter string) (int, error) {
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
	if filter != "" {
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
	}

	start := time.Now()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for time.Since(start) <= wait {
		select {
		case packet, _ := <-packetSource.Packets():
			if print {
				fmt.Println(packet)
				err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				if err != nil {
					return 0, err
				}
			}

			packetCount++
		default:

		}
	}

	return packetCount, nil

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
	n, _ := readTraffic(p.Name, false, "")

	if n != 0 {
		fmt.Println("Name: ", p.Name)
		fmt.Println("Description: ", p.Description)
		fmt.Print("got ", n, " packets per second\n\n")
	}

	wg.Done()
}
