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

// Geneve header structure
struct genevehdr {
    __u8 opt_len:6, ver:2;       // Option length and version
    __u8 rsvd:6, critical:1, control:1;  // Reserved, Critical, Control flags
    __be16 protocol_type;        // Protocol type (e.g., Geneve identifier)
    __u8 vni[3];                 // VNI (Virtual Network Identifier)
    __u8 reserved;               // Reserved byte
} __attribute__((packed));

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

    // Ensure there's enough space for adding the new option (4 bytes for vpc_id)
    if (options_end + 4 > options_start + MAX_LENGTH_OPTION) {
        return TC_ACT_PIPE;
    }

    //Look up vpc_id (key = 1) from the map
    __u32 key = 1; // Key for vpc_id
    __u32 *vpc_id = bpf_map_lookup_elem(&custom_data_map, &key);
    if (vpc_id) {
        // Manually move the data after options_end to the right to make space for the vpc_id
        __u8 *current_pos = (__u8 *)(long)skb->data_end;
        __u8 *new_pos = current_pos + 4;
        
        while (current_pos >= options_end) {
            *new_pos-- = *current_pos--;
        }

        // Add vpc_id to the end of the options
        *(__u32 *)options_end = bpf_htonl(*vpc_id);

        // Update the option length in the Geneve header
        geneve->opt_len += 1;

        // Update data_end
        skb->data_end += 4;

        // Update UDP length
        __u16 old_udp_len = bpf_ntohs(udp->len);
        __u16 new_udp_len = old_udp_len + 4;
        udp->len = bpf_htons(new_udp_len);
        // Update checksum UDP
        bpf_l4_csum_replace(skb, offsetof(struct udphdr, check), old_udp_len, new_udp_len, BPF_F_PSEUDO_HDR | sizeof(__u16));

        // Update IP total length
        __u16 old_ip_len = bpf_ntohs(ip->tot_len);
        __u16 new_ip_len = old_ip_len + 4;
        ip->tot_len = bpf_htons(new_ip_len);
        // update checksum IP
        bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_ip_len, new_ip_len, sizeof(__u16));
    }

    return TC_ACT_OK;
}

SEC("tc")
int custom_packet(struct __sk_buff *skb)
{
    return process_geneve(skb);
}

char _license[] SEC("license") = "GPL";
