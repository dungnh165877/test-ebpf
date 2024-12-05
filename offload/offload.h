//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

#define ICMP_HEADER_LENGTH 8

#define ETHER_TYPE_ARP 0x0806

struct packet_event {
  __u8  type;
  __u32 protocol;
  __u32 payload_len;
  __u32 saddr;
  __u32 daddr;
  __u16 src_port;
  __u16 dst_port;
  __u32 vni;
  __u16 ingress_port;
  __u16 egress_port;
} __attribute__((packed));

struct ip_prefix {
    __u32 base_ip;
    __u32 prefix_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ip_prefix);
} ip_block_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");
