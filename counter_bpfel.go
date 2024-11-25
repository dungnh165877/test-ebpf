// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadCounter returns the embedded CollectionSpec for counter.
func loadCounter() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_CounterBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load counter: %w", err)
	}

	return spec, err
}

// loadCounterObjects loads counter and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*counterObjects
//	*counterPrograms
//	*counterMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadCounterObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadCounter()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// counterSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type counterSpecs struct {
	counterProgramSpecs
	counterMapSpecs
}

// counterSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type counterProgramSpecs struct {
	ClassifyPacket *ebpf.ProgramSpec `ebpf:"classify_packet"`
}

// counterMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type counterMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
}

// counterObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadCounterObjects or ebpf.CollectionSpec.LoadAndAssign.
type counterObjects struct {
	counterPrograms
	counterMaps
}

func (o *counterObjects) Close() error {
	return _CounterClose(
		&o.counterPrograms,
		&o.counterMaps,
	)
}

// counterMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadCounterObjects or ebpf.CollectionSpec.LoadAndAssign.
type counterMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}

func (m *counterMaps) Close() error {
	return _CounterClose(
		m.Events,
	)
}

// counterPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadCounterObjects or ebpf.CollectionSpec.LoadAndAssign.
type counterPrograms struct {
	ClassifyPacket *ebpf.Program `ebpf:"classify_packet"`
}

func (p *counterPrograms) Close() error {
	return _CounterClose(
		p.ClassifyPacket,
	)
}

func _CounterClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed counter_bpfel.o
var _CounterBytes []byte
