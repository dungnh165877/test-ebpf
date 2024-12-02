package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	var objs customObjects
	if err := loadCustomObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	ifname := "enp1s0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		panic(err)
	}

	key := uint32(1)
	value := uint32(1)
	err = objs.CustomDataMap.Put(key, value)
	if err != nil {
		log.Fatalf("could not insert data into map: %s", err)
	}
	log.Printf("Inserted key=%d value=%d into eBPF map", key, value)

	// Attach the program to Egress TC.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.CustomPacket,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	log.Printf("Press Ctrl-C to exit and remove the program")
	<-stop
}
