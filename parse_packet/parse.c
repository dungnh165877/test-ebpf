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

struct packet_event {
  __u32 protocol;
  __u32 packet_len;
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 1024);
} events SEC(".maps");

SEC("xdp")
int classify_packet(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth+1) > data_end) return XDP_PASS;
  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    struct iphdr *ip = (struct iphdr *)(eth+1);
    if ((void *)(ip+1) > data_end) return XDP_PASS;

    struct packet_event evt = {};
    evt.packet_len = (__u32)(data_end - data);

    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip->ihl*4;
    if ((void *)(udp+1) > data_end) return XDP_PASS;

    // Check UDP destination port for Geneve
    if (udp->dest != bpf_htons(6081)) return XDP_PASS;

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

    // Check inner Ethertype
    if (geneve->protocol_type == bpf_htons(ETH_P_TEB)) {
      __u8 *options_start = (__u8 *)(geneve + 1); // Start of options after the Geneve header
      __u16 options_length = geneve->opt_len * 4;
      bpf_trace_printk("Geneve options length: %u bytes\n", options_length);

      for (__u16 i = 0; i < options_length; i++) {
        __u8 option_byte = options_start[i];
        bpf_trace_printk("Option[%u]: 0x%x\n", i, option_byte);
      }

      __u32 *vpc_id_ptr = (__u32 *)(options_start + options_length - 4);
      __u32 vpc_id = bpf_ntohl(*vpc_id_ptr);
      bpf_trace_printk("VPC ID: %u\n", vpc_id);

      struct ethhdr *inner_eth = (void *)geneve + sizeof(*geneve) + geneve->opt_len * 4;
      if ((void *)(inner_eth + 1) > data_end) return XDP_DROP;

      // Process inner IPv4 packet
      struct iphdr *inner_ip = (void *)inner_eth + sizeof(*inner_eth);
      if ((void *)(inner_ip + 1) > data_end) return XDP_DROP;

      if (inner_ip->protocol == IPPROTO_TCP) {
        evt.protocol = IPPROTO_TCP;

        struct tcphdr *tcp1 = (void *)inner_ip + inner_ip->ihl*4;
        if ((void *)(tcp1+1) > data_end) return XDP_PASS;

        evt.sport = bpf_ntohl(tcp1->source);
        evt.dport = bpf_ntohl(tcp1->dest);
      } else if (inner_ip->protocol == IPPROTO_UDP) {
        evt.protocol = IPPROTO_UDP;
        
        struct udphdr *udp1 = (void *)inner_ip + inner_ip->ihl*4;
        if ((void *)(udp1+1) > data_end) return XDP_PASS;

        evt.sport = bpf_ntohl(udp1->source);
        evt.dport = bpf_ntohl(udp1->dest);
      } else if (inner_ip->protocol == IPPROTO_ICMP) {
        evt.protocol = IPPROTO_ICMP;
      }

      evt.saddr = bpf_ntohl(inner_ip->saddr);
      evt.daddr = bpf_ntohl(inner_ip->daddr);

      bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
