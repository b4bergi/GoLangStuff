package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	device        = "\\Device\\NPF_{3F8A9504-56D8-4316-B344-89262D14817D}"
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

	// devices, err := pcap.FindAllDevs()
    // if err != nil {
    //     log.Fatal(err)
    // }

    // fmt.Println("Devices found:")
    // for _, device := range devices {
    //     fmt.Println("\nName: ", device.Name)
    //     fmt.Println("Description: ", device.Description)
    //     fmt.Println("Devices addresses: ", device.Description)
    //     for _, address := range device.Addresses {
    //         fmt.Println("- IP address: ", address.IP)
    //         fmt.Println("- Subnet mask: ", address.Netmask)
    //     }
    // }
}
