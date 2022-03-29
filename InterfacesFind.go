package main

import (
	"fmt"
	"net"
)

func main() {
	interfaces, _ := net.Interfaces()
	for _, inter := range interfaces {
		fmt.Println("Index :", inter.Index)
		fmt.Println("Name  :", inter.Name)
		fmt.Println("HWaddr:", inter.HardwareAddr)
		fmt.Println("MTU   :", inter.MTU)
		fmt.Println("Flags :", inter.Flags)
		addrs,_ := inter.Addrs()
		for _, ipaddr := range addrs {
			fmt.Println("Addr  :", ipaddr)
		}
		fmt.Println()
	}
}
