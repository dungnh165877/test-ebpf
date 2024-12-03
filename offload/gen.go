package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go offload offload.c -- -I/usr/include/x86_64-linux-gnu
