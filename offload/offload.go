package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type PacketEvent struct {
	Protocol   uint32
	PayloadLen uint32
	SrcAddr    uint32
	DstAddr    uint32
	SrcPort    uint16
	DstPort    uint16
	VNI        uint32
}

const (
	ProtocolTCP  = 6
	ProtocolUDP  = 17
	ProtocolICMP = 1
)

type IPPrefix struct {
	BaseIP    uint32
	PrefixLen uint32
}

func cidrToIPPrefix(cidr string) (IPPrefix, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPPrefix{}, err
	}

	baseIP := binary.BigEndian.Uint32(ip.To4())
	prefixLen, _ := ipnet.Mask.Size()

	return IPPrefix{BaseIP: baseIP, PrefixLen: uint32(prefixLen)}, nil
}

func main() {
	startLoad := time.Now()
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	var objs offloadObjects
	if err := loadOffloadObjects(&objs, nil); err != nil {
		panic(err)
	}
	// defer objs.Close()

	cidr := "10.30.5.0/24"
	ipPrefix, err := cidrToIPPrefix(cidr)
	if err != nil {
		log.Fatalf("Invalid CIDR: %v", err)
	}

	if err := objs.IpBlockMap.Put(uint32(0), ipPrefix); err != nil {
		log.Fatalf("Failed to update BPF map: %v", err)
	}

	ifname := "enp1s0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		panic(err)
	}

	linkXDP, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.EbpfOffload,
		Interface: iface.Index,
	})
	if err != nil {
		panic(err)
	}
	// defer linkXDP.Close()

	loadDuration := time.Since(startLoad)
	log.Printf("Time to load eBPF program: %v\n", loadDuration)
	log.Printf("connected to %s interface", ifname)

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	// defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if !errors.Is(err, perf.ErrClosed) {
					log.Printf("error reading from perf reader: %v", err)
				}

				continue
			}
			var event PacketEvent
			if err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("error parsing event: %v", err)
				continue
			}
			protocol := ""
			switch event.Protocol {
			case ProtocolTCP:
				protocol = "tcp"
			case ProtocolUDP:
				protocol = "udp"
			case ProtocolICMP:
				protocol = "icmp"
			}
			// if event.Protocol != ProtocolUDP {
			// 	continue
			// }

			log.Printf("packet received: protocol=%s payload_length=%d, src:%s, dst:%s, srcp:%d, dstp:%d, vni: %d",
				protocol,
				event.PayloadLen,
				IntToIP(event.SrcAddr),
				IntToIP(event.DstAddr),
				event.SrcPort,
				event.DstPort,
				event.VNI,
			)
		}
	}()

	<-sig
	log.Println("Exiting...")

	startUnload := time.Now()
	if err := rd.Close(); err != nil {
		log.Printf("Error closing perf reader: %v", err)
	}
	if err := linkXDP.Close(); err != nil {
		log.Printf("Error detaching XDP: %v", err)
	}
	if err := objs.Close(); err != nil {
		log.Printf("Error closing eBPF objects: %v", err)
	}
	unloadDuration := time.Since(startUnload)
	log.Printf("Time to unload eBPF program: %v\n", unloadDuration)
}

func IntToIP(nn uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip.String()
}
