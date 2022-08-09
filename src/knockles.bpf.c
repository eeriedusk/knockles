#include "vmlinux.h"
#include "knockles_event.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#define  PORT   80

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/****************************************************/
/*!
 *  \brief  Ring buffer map use to send event
 *          to the userland program
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1);
} rb SEC(".maps");

struct netif_receive_skb_format{
    unsigned long long   h;
    void                *skbaddr;
    unsigned int         len;
};

SEC("tp/net/netif_receive_skb")
int trace_net_netif_receive_skb(struct netif_receive_skb_format *ctx){
    struct sk_buff *skb = ctx->skbaddr;
    unsigned char *head;
    u16 transport_header, dst;
    struct tcphdr tcp_hdr;
    
    bpf_probe_read(&head, sizeof(unsigned char *), &skb->head);
    bpf_probe_read(&transport_header, sizeof(u16), &skb->transport_header);
    bpf_probe_read(&tcp_hdr, sizeof(tcp_hdr), (struct tcphdr *)(head+transport_header));
    dst = ((tcp_hdr.dest & 0xff) << 8) | (tcp_hdr.dest >> 8);
    if(dst != PORT) return 0;
    if(tcp_hdr.syn != 1) return 0;
    
    u16 network_header;
    struct iphdr ip_hdr;
    bpf_probe_read(&network_header, sizeof(u16), &skb->network_header);
    bpf_probe_read(&ip_hdr, sizeof(ip_hdr), (struct iphdr *)(head+network_header));
    
    event_t* event;
    event = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if(!event) return 0;
    
    event->id  = (uint16_t) ((ip_hdr.id & 0xff) << 8) | (ip_hdr.id >> 8);
    event->seq = (uint32_t) __builtin_bswap32(tcp_hdr.seq);
    event->win = (uint16_t) ((tcp_hdr.window & 0xff) << 8) | (tcp_hdr.window >> 8);
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
};
