//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>

#define GENEVE_PORT 6081
#define MAX_LENGTH_OPTION 252
#define OPT_CLASS 1001
#define OPT_TYPE 10

// Geneve header option structure
struct geneve_opt_hdr {
	__be16 opt_class;
	__u8 type;
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 length:5, rsvd:3;
#else
	__u8 rsvd:3, length:5;
#endif
};

struct geneve_opt_data {
    __u32 vpc_id;
};

// Geneve header structure
struct genevehdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 opt_len:6, ver:2;
	__u8 rsvd:6, critical:1, control:1;
#else
	__u8 ver:2, opt_len:6;
	__u8 control:1, critical:1, rsvd:6;
#endif
	__be16 protocol_type;
	__u8 vni[3];
	__u8 reserved;
};

// Define a generic data map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);  // Support up to 32 entries
    __type(key, __u32);        // Key is a unique identifier for each type of data (e.g., vpc_id = 1, tenant_id)
    __type(value, __u32);      // Value is the corresponding data
} custom_data_map SEC(".maps");

// Function to parse Geneve options and add custom data
static __always_inline int process_geneve(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_PIPE;

    struct iphdr *ip = data + sizeof(*eth);

    // Check IP header
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_UDP)
        return TC_ACT_PIPE;

    struct udphdr *udp = (void *)(ip) + (ip->ihl * 4);
    
    // Check UDP port for Geneve
    if ((void *)(udp + 1) > data_end || bpf_ntohs(udp->dest) != GENEVE_PORT)
        return TC_ACT_PIPE;

    struct genevehdr *geneve = (struct genevehdr *)(udp + 1);

    // Check the length of Geneve options
    __u8 *options_start = (__u8 *)(geneve + 1); // Start of options after the Geneve header
    __u16 options_length = geneve->opt_len * 4;

    // Calculate the end of the current options
    __u8 *options_end = options_start + options_length;

    __u8 length_extent_opt = sizeof(struct geneve_opt_hdr) + sizeof(struct geneve_opt_data);

    // Ensure there's enough space for adding the new option (4 bytes for vpc_id)
    if (options_end + length_extent_opt > options_start + MAX_LENGTH_OPTION) {
        return TC_ACT_PIPE;
    }

    //Look up vpc_id (key = 1) from the map
    __u32 key = 1; // Key for vpc_id
    __u32 *vpc_id = bpf_map_lookup_elem(&custom_data_map, &key);
    if (vpc_id) {
        if (bpf_skb_adjust_room(skb, length_extent_opt, BPF_ADJ_ROOM_MAC, 0) < 0) {
            return TC_ACT_SHOT;
        }

        void *new_data_end = (void *)(long)skb->data_end;

        struct geneve_opt_hdr opt_hdr = {
            .opt_class = bpf_htons(OPT_CLASS),
            .type = OPT_TYPE,
            .length = sizeof(struct geneve_opt_data) / 4
        };

        struct geneve_opt_data opt_data = {
            .vpc_id = *vpc_id
        };

        if ((void *)(options_end + sizeof(opt_hdr) + sizeof(opt_data)) > new_data_end)
            return TC_ACT_PIPE;

        __u32 geneve_opt_off = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct genevehdr) + geneve->opt_len * 4;

        if (bpf_skb_store_bytes(skb, geneve_opt_off, &opt_hdr, sizeof(struct geneve_opt_hdr), 0) < 0){
           return TC_ACT_SHOT;
        }
        
        if (bpf_skb_store_bytes(skb, geneve_opt_off + sizeof(struct geneve_opt_hdr), &opt_data, sizeof(struct geneve_opt_data), 0) < 0){
           return TC_ACT_SHOT;
        }

        // Update the option length in the Geneve header
        geneve->opt_len += length_extent_opt/4;
    }

    return TC_ACT_OK;
}

SEC("tc")
int custom_packet(struct __sk_buff *skb)
{
    return process_geneve(skb);
}

char _license[] SEC("license") = "GPL";
