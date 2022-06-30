package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type filters struct {
	netProtocols   []string
	transProtocols []string
	ports          []string
	IPs            []string
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
		filter = createFilter()
		fmt.Println("Starting with filters.")
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
	fmt.Println("Write network protocols (or \"no\" if you don't need this filter):")
	net := " "
	fmt.Scanln(&net)

	fmt.Println("Write transport protocols (or \"no\" if you don't need this filter):")
	trans := " "
	fmt.Scanln(&trans)

	fmt.Println("Write ports (or \"no\" if you don't need this filter):")
	port := ""
	fmt.Scanln(&port)

	fmt.Println("Write IPs (or \"no\" if you don't need this filter):")
	ips := ""
	fmt.Scanln(&ips)

	f := filters{nil, nil, nil, nil}
	if net != "no" {
		f.netProtocols = strings.Split(net, ",")
	}
	if trans != "no" {
		f.transProtocols = strings.Split(trans, ",")
	}
	if port != "no" {
		f.ports = strings.Split(port, ",")
	}

	if ips != "no" {
		f.IPs = strings.Split(ips, ",")
	}
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

	filters := 0
	isFound := false

	if filter.netProtocols != nil {
		for _, prot := range filter.netProtocols {
			if isFound {
				isFound = false
				break
			}
			for _, l := range packet.Layers() {
				if strings.EqualFold(l.LayerType().String(), prot) {
					filters += 1
					isFound = true
					break
				}
			}
		}
	} else {
		filters += 1
	}

	if filter.transProtocols != nil {
		for _, prot := range filter.transProtocols {
			if isFound {
				isFound = false
				break
			}
			for _, l := range packet.Layers() {
				if strings.EqualFold(l.LayerType().String(), prot) {
					filters += 2
					isFound = true
					break
				}
			}
		}
	} else {
		filters += 2
	}

	if filter.ports != nil {
		for _, port := range filter.ports {
			if isFound {
				isFound = false
				break
			}
			for _, l := range packet.Layers() {
				p, err := strconv.Atoi(port)
				if err == nil && getPort(l) == p {
					filters += 4
					isFound = true
					break
				}
			}
		}
	} else {
		filters += 4
	}

	if filter.IPs != nil {
		for _, reqIP := range filter.IPs {
			if isFound {
				isFound = false
				break
			}
			for _, l := range packet.Layers() {
				ip, err := getIP(l)
				if err == nil && ip == reqIP {
					isFound = true
					filters += 8
					break
				}
			}
		}
	} else {
		filters += 8
	}

	if filters == 15 {
		return true
	}

	return false
}

func getPort(l gopacket.Layer) int {
	contents := gopacket.LayerString(l)
	if !strings.Contains(contents, "DstPort") {
		return -1
	}

	headers := strings.Split(contents, " ")

	for _, h := range headers {
		if strings.Contains(h, "DstPort") {
			a := 0
			for _, d := range h {
				if unicode.IsDigit(d) {
					a *= 10
					a += int(d - '0')
				}
			}
			return a
		}
	}
	return -2
}

func getIP(l gopacket.Layer) (string, error) {
	contents := gopacket.LayerString(l)
	if !strings.Contains(contents, "DstIP") {
		return "err", errors.New("wrong layer")
	}

	headers := strings.Split(contents, " ")

	for _, h := range headers {
		if strings.Contains(h, "DstIP") {
			a := h[6:]
			return a, nil
		}
	}
	return "err", errors.New("something strange")
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
