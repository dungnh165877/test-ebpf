package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type PacketEvent struct {
	Protocol     uint32
	PacketLength uint32
	SrcAddr      uint32
	DstAddr      uint32
	SrcPort      uint16
	DstPort      uint16
}

const (
	ProtocolTCP  = 6
	ProtocolUDP  = 17
	ProtocolICMP = 1
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	ifname := "enp1s0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		panic(err)
	}

	linkXDP, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.ClassifyPacket,
		Interface: iface.Index,
	})
	if err != nil {
		panic(err)
	}
	defer linkXDP.Close()

	log.Printf("connected to %s interface", ifname)

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer rd.Close()

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

			log.Printf("packet received: protocol=%s packet_length=%d, src:%s, dst:%s, srcp:%d, dstp:%d",
				protocol,
				event.PacketLength,
				IntToIP(event.SrcAddr),
				IntToIP(event.DstAddr),
				event.SrcPort,
				event.DstPort,
			)
		}
	}()

	<-sig
	log.Println("Exiting...")
}

func IntToIP(nn uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip.String()
}
