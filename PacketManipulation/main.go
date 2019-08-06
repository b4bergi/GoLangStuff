package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
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
	if len(os.Args) > 1 {
		device = os.Args[1]
	}

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

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetFrame := ethernetLayer.(*layers.Ethernet)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ipPacket, _ := ipLayer.(*layers.IPv4)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		icmpPacket := icmpLayer.(*layers.ICMPv4)

		if icmpPacket.TypeCode.String() == "EchoRequest" {
			if len(icmpPacket.Payload) > 0 {
				log.Println("Info: EchoRequest recieved")
			} else {
				log.Println("Warn: Empty EchoRequest recieved")
				ethernetFrameCopy := *ethernetFrame
				ipPacketCopy := *ipPacket
				icmpPacketCopy := *icmpPacket

				ethernetFrameCopy.SrcMAC = ethernetFrame.DstMAC
				ethernetFrameCopy.DstMAC = ethernetFrame.SrcMAC

				ipPacketCopy.SrcIP = ipPacket.DstIP
				ipPacketCopy.DstIP = ipPacket.SrcIP

				icmpPacketCopy.TypeCode = layers.ICMPv4TypeEchoReply

				var buffer gopacket.SerializeBuffer
				var options gopacket.SerializeOptions
				options.ComputeChecksums = true

				buffer = gopacket.NewSerializeBuffer()
				gopacket.SerializeLayers(buffer,
					options,
					&ethernetFrameCopy,
					&ipPacketCopy,
					&icmpPacketCopy,
					gopacket.Payload(icmpPacketCopy.Payload))

				newMessage := buffer.Bytes()
				err = handle.WritePacketData(newMessage)
				if err != nil {
					log.Fatal(err)
				}

			}
		}

		fmt.Println("Source: " + ipPacket.SrcIP.String())
		fmt.Println("Destination: " + ipPacket.DstIP.String())
		fmt.Println("Protocol: ", ipPacket.Protocol)
		fmt.Println("Source: " + ipPacket.SrcIP.String())

		fmt.Println("---------------")

		fmt.Println("ICMP Code: ", icmpPacket.TypeCode)
		fmt.Println("ICMP Sequence Nr: ", icmpPacket.Seq)
		fmt.Println("Payload length: ", len(icmpPacket.Payload))
		fmt.Println("Payload data: ", icmpPacket.Payload)
		fmt.Println("Payload data to string: ", string(icmpPacket.Payload))
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
