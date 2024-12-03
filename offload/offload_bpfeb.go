// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type offloadIpPrefix struct {
	BaseIp    uint32
	PrefixLen uint32
}

// loadOffload returns the embedded CollectionSpec for offload.
func loadOffload() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_OffloadBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load offload: %w", err)
	}

	return spec, err
}

// loadOffloadObjects loads offload and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*offloadObjects
//	*offloadPrograms
//	*offloadMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadOffloadObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadOffload()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// offloadSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type offloadSpecs struct {
	offloadProgramSpecs
	offloadMapSpecs
}

// offloadSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type offloadProgramSpecs struct {
	EbpfOffload *ebpf.ProgramSpec `ebpf:"ebpf_offload"`
}

// offloadMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type offloadMapSpecs struct {
	Events     *ebpf.MapSpec `ebpf:"events"`
	IpBlockMap *ebpf.MapSpec `ebpf:"ip_block_map"`
}

// offloadObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadOffloadObjects or ebpf.CollectionSpec.LoadAndAssign.
type offloadObjects struct {
	offloadPrograms
	offloadMaps
}

func (o *offloadObjects) Close() error {
	return _OffloadClose(
		&o.offloadPrograms,
		&o.offloadMaps,
	)
}

// offloadMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadOffloadObjects or ebpf.CollectionSpec.LoadAndAssign.
type offloadMaps struct {
	Events     *ebpf.Map `ebpf:"events"`
	IpBlockMap *ebpf.Map `ebpf:"ip_block_map"`
}

func (m *offloadMaps) Close() error {
	return _OffloadClose(
		m.Events,
		m.IpBlockMap,
	)
}

// offloadPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadOffloadObjects or ebpf.CollectionSpec.LoadAndAssign.
type offloadPrograms struct {
	EbpfOffload *ebpf.Program `ebpf:"ebpf_offload"`
}

func (p *offloadPrograms) Close() error {
	return _OffloadClose(
		p.EbpfOffload,
	)
}

func _OffloadClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed offload_bpfeb.o
var _OffloadBytes []byte
