//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf_common.h>

#define ICMP_HEADER_LENGTH 8

struct packet_event {
  __u32 protocol;
  __u32 payload_len;
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u32 vni;
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

SEC("xdp")
int ebpf_offload(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  __u32 key = 0;
  struct ip_prefix *prefix = bpf_map_lookup_elem(&ip_block_map, &key);
  if (!prefix) return XDP_PASS;
  __u32 subnet_mask = (0xFFFFFFFF << (32 - prefix->prefix_len));

  struct ethhdr *eth = data;
  if ((void *)(eth+1) > data_end) return XDP_PASS;
  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *ip = (struct iphdr *)(eth+1);
    if ((void *)(ip+1) > data_end) return XDP_PASS;

    if ((bpf_ntohl(ip->saddr) & subnet_mask) == (prefix->base_ip & subnet_mask)) {
        return XDP_DROP;
    }

    struct packet_event evt = {};

    if (ip->protocol == IPPROTO_ICMP) {
      evt.protocol = IPPROTO_ICMP;
      evt.saddr = bpf_ntohl(ip->saddr);
      evt.daddr = bpf_ntohl(ip->daddr);
      evt.payload_len = data_end - (void *)(ip + ip->ihl*4 + ICMP_HEADER_LENGTH);
      bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
      return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_TCP) {
      evt.protocol = IPPROTO_TCP;
      evt.saddr = bpf_ntohl(ip->saddr);
      evt.daddr = bpf_ntohl(ip->daddr);
      struct tcphdr *tcph = (void *)ip + ip->ihl*4;
      if ((void *)(tcph+1) > data_end) return XDP_PASS;
      evt.sport = bpf_ntohl(tcph->source);
      evt.dport = bpf_ntohl(tcph->dest);
      evt.payload_len = data_end - (void *)(tcph + sizeof(struct tcphdr));
      bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
      return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip->ihl*4;
    if ((void *)(udp+1) > data_end) return XDP_PASS;

    // Check UDP destination port for Geneve
    if (udp->dest != bpf_htons(6081)) {
      evt.protocol = IPPROTO_UDP;
      evt.saddr = bpf_ntohl(ip->saddr);
      evt.daddr = bpf_ntohl(ip->daddr);
      evt.sport = bpf_ntohl(udp->source);
      evt.dport = bpf_ntohl(udp->dest);
      evt.payload_len = data_end - (void *)(udp + sizeof(struct udphdr));
      bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
      return XDP_PASS;
    };

    // Geneve Header (8 bytes fixed size)
    struct genevehdr {
      __u8 opt_len:6, ver:2;
      __u8 rsvd:6, critical:1, control:1;
      __be16 protocol_type;
      __u8 vni[3];
      __u8 reserved;
    } __attribute__((packed));

    struct genevehdr *geneve = (void *)(udp + 1);
    if ((void *)(geneve + 1) > data_end) return XDP_DROP;

    evt.vni = geneve->vni[0] << 16 | geneve->vni[1] << 8 | geneve->vni[2];

    // Check inner Ethertype
    if (geneve->protocol_type == bpf_htons(ETH_P_TEB)) {
      __u8 *options_start = (__u8 *)(geneve + 1); // Start of options after the Geneve header
      __u16 options_length = geneve->opt_len * 4;
      void *inner_packet_start = (void *)geneve + sizeof(*geneve) + geneve->opt_len * 4;
      if (inner_packet_start > data_end) return XDP_DROP;

      struct ethhdr *inner_eth = inner_packet_start;
      if ((void *)(inner_eth + 1) > data_end) return XDP_DROP;

      // Process inner IPv4 packet
      struct iphdr *inner_ip = (void *)inner_eth + sizeof(*inner_eth);
      if ((void *)(inner_ip + 1) > data_end) return XDP_DROP;

      if ((bpf_ntohl(inner_ip->saddr) & subnet_mask) == (prefix->base_ip & subnet_mask)) {
        return XDP_DROP;
      }

      if (inner_ip->protocol == IPPROTO_TCP) {
        evt.protocol = IPPROTO_TCP;

        struct tcphdr *tcp1 = (void *)inner_ip + inner_ip->ihl*4;
        if ((void *)(tcp1+1) > data_end) return XDP_PASS;

        evt.sport = bpf_ntohl(tcp1->source);
        evt.dport = bpf_ntohl(tcp1->dest);
        evt.payload_len = data_end - (void *)(tcp1 + sizeof(struct tcphdr));
      } else if (inner_ip->protocol == IPPROTO_UDP) {
        evt.protocol = IPPROTO_UDP;
        
        struct udphdr *udp1 = (void *)inner_ip + inner_ip->ihl*4;
        if ((void *)(udp1+1) > data_end) return XDP_PASS;

        evt.sport = bpf_ntohl(udp1->source);
        evt.dport = bpf_ntohl(udp1->dest);
        evt.payload_len = data_end - (void *)(udp1 + sizeof(struct udphdr));
      } else if (inner_ip->protocol == IPPROTO_ICMP) {
        evt.protocol = IPPROTO_ICMP;
        evt.payload_len = data_end - (void *)(inner_ip + inner_ip->ihl*4 + ICMP_HEADER_LENGTH);
      }

      evt.saddr = bpf_ntohl(inner_ip->saddr);
      evt.daddr = bpf_ntohl(inner_ip->daddr);

      bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
