#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>

typedef struct VirtualIPArgs {
    uint32_t ip;
    uint16_t port;
    uint8_t mac_address[6];
    uint16_t num_reals;
} __attribute__((packed)) VirtualIPArgs;

typedef struct RealAddress {
    uint32_t ip;
    uint16_t port;
    uint8_t mac_address[6];
} __attribute__((packed)) RealAddress;

BPF_HASH(arguments, u32, VirtualIPArgs, 1);
BPF_HASH(reals, u32, RealAddress, 256);

int xdp_entry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    uint32_t key = 0;

    if ((void *)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end) {
            if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end) {
                    VirtualIPArgs *args = arguments.lookup(&key);
                    if (args == 0) {
                        return XDP_PASS;
                    }
                    if (!(ntohs(udp->dest) == args->port &&
                          ip->saddr == htonl(args->ip))) {
                        bpf_trace_printk(
                            "UDP ip or port does not match, dropping.");
                        return XDP_PASS;
                    }
                    uint32_t reals_key =
                        (ip->saddr + udp->source) % args->num_reals;
                    RealAddress *real = reals.lookup(&reals_key);
                    if (real == 0) {
                        return XDP_PASS;
                    }
                    bpf_trace_printk("Processing packet. Sending to %d:%d",
                                     real->ip, real->port);
                    udp->dest = htons(real->port);
                    ip->daddr = htonl(real->ip);
                    memcpy(eth->h_dest, real->mac_address, 6);
                    memcpy(eth->h_source, args->mac_address, 6);
                    return XDP_TX;
                }
            }
        }
    }
    return XDP_PASS;
}
