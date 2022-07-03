package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"log"
	"net"
	"net/http"
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
	dstPorts       []string
	dstIPs         []string
	srcIPs         []string
}

func sniffer() {
	name, err := os.Hostname()
	if err != nil {
		fmt.Printf("Oops: %v\n", err)
		return
	}

	addrs, err := net.LookupHost(name)
	if err != nil {
		fmt.Printf("Oops: %v\n", err)
		return
	}

	for _, a := range addrs {
		fmt.Println(a)
	}

	printInterfaces()
	name = ""

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
	_, err = readTraffic(addrs, name, true, filter)
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

	fmt.Println("Write dstIPs (or \"no\" if you don't need this filter):")
	dstIPs := ""
	fmt.Scanln(&dstIPs)

	fmt.Println("Write srcIPs (or \"no\" if you don't need this filter):")
	srcIPs := ""
	fmt.Scanln(&srcIPs)

	f := filters{nil, nil, nil, nil, nil}
	if net != "no" {
		f.netProtocols = strings.Split(net, ",")
	}
	if trans != "no" {
		f.transProtocols = strings.Split(trans, ",")
	}
	if port != "no" {
		f.dstPorts = strings.Split(port, ",")
	}

	if dstIPs != "no" {
		f.dstIPs = strings.Split(dstIPs, ",")
	}

	if srcIPs != "no" {
		f.dstIPs = strings.Split(srcIPs, ",")
	}
	return f
}

func readTraffic(addrs []string, name string, print bool, filter filters) (int, error) {
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
				go processHttp(packet, addrs)
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

func processHttp(packet gopacket.Packet, addrs []string) {
	if isHttp(packet, addrs) {
		reader := bytes.NewReader(packet.ApplicationLayer().Payload())
		req, err := http.ReadRequest(bufio.NewReader(reader))
		if err == nil {
			//todo решить что делать с этой ошибкой
		}
		p := proxy{}
		//p.ServeHTTP()
	}
}

func isHttp(packet gopacket.Packet, addrs []string) bool {
	f := filters{
		netProtocols:   nil,
		transProtocols: nil,
		dstPorts:       []string{"80"},
		dstIPs:         nil,
		srcIPs:         addrs,
	}

	return applyFilter(packet, f)
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

	if filter.dstPorts != nil {
		for _, port := range filter.dstPorts {
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

	if filter.dstIPs != nil {
		for _, reqIP := range filter.dstIPs {
			if isFound {
				isFound = false
				break
			}
			for _, l := range packet.Layers() {
				ip, err := getDstIP(l)
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

	if filter.srcIPs != nil {
		for _, reqIP := range filter.srcIPs {
			if isFound {
				isFound = false
				break
			}
			for _, l := range packet.Layers() {
				ip, err := getSrcIP(l)
				if err == nil && ip == reqIP {
					isFound = true
					filters += 16
					break
				}
			}
		}
	} else {
		filters += 16
	}

	if filters == 31 {
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

func getDstIP(l gopacket.Layer) (string, error) {
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

func getSrcIP(l gopacket.Layer) (string, error) {
	contents := gopacket.LayerString(l)
	if !strings.Contains(contents, "SrcIP") {
		return "err", errors.New("wrong layer")
	}

	headers := strings.Split(contents, " ")

	for _, h := range headers {
		if strings.Contains(h, "SrcIP") {
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
	n, _ := readTraffic(nil, p.Name, false, filters{})

	if n != 0 {
		fmt.Println("Name: ", p.Name)
		fmt.Println("Description: ", p.Description)
		fmt.Print("got ", n, " packets per second\n\n")
	}

	wg.Done()
}
