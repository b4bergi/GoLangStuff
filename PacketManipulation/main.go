package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	device        = "WiFi"
	snaplen int32 = 65535
	promisc       = false
	err     error
	timeout = -1 * time.Second
	handle  *pcap.Handle
)

func main() {
	handle, err = pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter = "src host 172.20.1.8 and icmp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetsource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetsource.Packets() {
		fmt.Println("Ping:")
		fmt.Println(packet)
	}
}
