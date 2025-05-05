#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/inet.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Richard Callaby");
MODULE_DESCRIPTION("Extended Kernel-Level Packet Sniffer (IPv4/IPv6 + Payloads)");
MODULE_VERSION("0.01");

#define PAYLOAD_PRINT_LEN 32

// ---------------------- IPv4 Hook ----------------------

static unsigned int ipv4_packet_hook(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    unsigned char *payload;
    int payload_len;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    printk(KERN_INFO "[IPv4] SRC: %pI4 DST: %pI4 PROTO: %u\n",
           &iph->saddr, &iph->daddr, iph->protocol);

    switch (iph->protocol) {
        case IPPROTO_TCP:
            tcph = tcp_hdr(skb);
            printk(KERN_INFO "[TCP] SRC_PORT: %u DST_PORT: %u\n",
                   ntohs(tcph->source), ntohs(tcph->dest));

            payload = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
            payload_len = skb_tail_pointer(skb) - payload;
            break;

        case IPPROTO_UDP:
            udph = udp_hdr(skb);
            printk(KERN_INFO "[UDP] SRC_PORT: %u DST_PORT: %u\n",
                   ntohs(udph->source), ntohs(udph->dest));

            payload = (unsigned char *)(udph + 1);
            payload_len = skb_tail_pointer(skb) - (unsigned char *)payload;
            break;

        case IPPROTO_ICMP:
            printk(KERN_INFO "[ICMP] Packet Detected\n");
            payload = (unsigned char *)(iph + 1);
            payload_len = skb_tail_pointer(skb) - (unsigned char *)payload;
            break;

        default:
            printk(KERN_INFO "[OTHER IPv4] Protocol: %u\n", iph->protocol);
            return NF_ACCEPT;
    }

    if (payload_len > 0) {
        int i, max = min(payload_len, PAYLOAD_PRINT_LEN);
        printk(KERN_INFO "[PAYLOAD] %d bytes:\n", max);
        for (i = 0; i < max; i++)
            printk(KERN_CONT "%02x ", payload[i]);
        printk(KERN_CONT "\n");
    }

    return NF_ACCEPT;
}

// ---------------------- IPv6 Hook ----------------------

static unsigned int ipv6_packet_hook(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state)
{
    struct ipv6hdr *ip6h;
    unsigned char *payload;
    int payload_len;

    if (!skb || skb->protocol != htons(ETH_P_IPV6))
        return NF_ACCEPT;

    ip6h = ipv6_hdr(skb);
    if (!ip6h)
        return NF_ACCEPT;

    printk(KERN_INFO "[IPv6] SRC: %pI6 DST: %pI6 NEXTHDR: %u\n",
           &ip6h->saddr, &ip6h->daddr, ip6h->nexthdr);

    payload = (unsigned char *)(ip6h + 1);
    payload_len = skb_tail_pointer(skb) - payload;

    if (payload_len > 0) {
        int i, max = min(payload_len, PAYLOAD_PRINT_LEN);
        printk(KERN_INFO "[PAYLOAD] %d bytes:\n", max);
        for (i = 0; i < max; i++)
            printk(KERN_CONT "%02x ", payload[i]);
        printk(KERN_CONT "\n");
    }

    return NF_ACCEPT;
}

// ---------------------- Hook Registration ----------------------

static struct nf_hook_ops netfilter_ops_ipv4;
static struct nf_hook_ops netfilter_ops_ipv6;

static int __init sniffer_init(void)
{
    netfilter_ops_ipv4.hook = ipv4_packet_hook;
    netfilter_ops_ipv4.pf = PF_INET;
    netfilter_ops_ipv4.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops_ipv4.priority = NF_IP_PRI_FIRST;

    netfilter_ops_ipv6.hook = ipv6_packet_hook;
    netfilter_ops_ipv6.pf = PF_INET6;
    netfilter_ops_ipv6.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops_ipv6.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_ops_ipv4);
    nf_register_net_hook(&init_net, &netfilter_ops_ipv6);

    printk(KERN_INFO "Extended Packet Sniffer Module Loaded\n");
    return 0;
}

static void __exit sniffer_exit(void)
{
    nf_unregister_net_hook(&init_net, &netfilter_ops_ipv4);
    nf_unregister_net_hook(&init_net, &netfilter_ops_ipv6);
    printk(KERN_INFO "Extended Packet Sniffer Module Unloaded\n");
}

module_init(sniffer_init);
module_exit(sniffer_exit);
