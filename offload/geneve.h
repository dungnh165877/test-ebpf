//go:build ignore

#include <linux/if_ether.h>

#define GENEVE_UDP_PORT 6081

// Geneve Header (8 bytes fixed size)
struct genevehdr {
    __u8 opt_len:6, ver:2;
    __u8 rsvd:6, critical:1, control:1;
    __be16 protocol_type;
    __u8 vni[3];
    __u8 reserved;
} __attribute__((packed));

struct genevehdr_opt {
  __be16 opt_class;
  __u8 type;
  __u8 length:5, rsvd:3;
} __attribute__((packed));

struct genevehdr_opt_data {
    __be16 ingress_port:15, rsvd:1;
    __be16 egress_port: 16;
} __attribute__((packed));
