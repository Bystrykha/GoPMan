package main

import (
	"fmt"
)

func main() {

	fmt.Println("do you need sniffer (1) or proxy (2)?")
	prog := 1
	fmt.Scanln(&prog)
	switch prog {
	case 1:
		sniffer()
		break
	case 2:
		startProxy()
		break
	default:
		fmt.Println("wrong program")
	}
}
