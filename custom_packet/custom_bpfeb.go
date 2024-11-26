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

// loadCustom returns the embedded CollectionSpec for custom.
func loadCustom() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_CustomBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load custom: %w", err)
	}

	return spec, err
}

// loadCustomObjects loads custom and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*customObjects
//	*customPrograms
//	*customMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadCustomObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadCustom()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// customSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type customSpecs struct {
	customProgramSpecs
	customMapSpecs
}

// customSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type customProgramSpecs struct {
	CustomPacket *ebpf.ProgramSpec `ebpf:"custom_packet"`
}

// customMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type customMapSpecs struct {
	CustomDataMap *ebpf.MapSpec `ebpf:"custom_data_map"`
}

// customObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadCustomObjects or ebpf.CollectionSpec.LoadAndAssign.
type customObjects struct {
	customPrograms
	customMaps
}

func (o *customObjects) Close() error {
	return _CustomClose(
		&o.customPrograms,
		&o.customMaps,
	)
}

// customMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadCustomObjects or ebpf.CollectionSpec.LoadAndAssign.
type customMaps struct {
	CustomDataMap *ebpf.Map `ebpf:"custom_data_map"`
}

func (m *customMaps) Close() error {
	return _CustomClose(
		m.CustomDataMap,
	)
}

// customPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadCustomObjects or ebpf.CollectionSpec.LoadAndAssign.
type customPrograms struct {
	CustomPacket *ebpf.Program `ebpf:"custom_packet"`
}

func (p *customPrograms) Close() error {
	return _CustomClose(
		p.CustomPacket,
	)
}

func _CustomClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed custom_bpfeb.o
var _CustomBytes []byte
