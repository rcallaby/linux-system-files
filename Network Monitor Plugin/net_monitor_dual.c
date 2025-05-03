#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("RichardCallaby");
MODULE_DESCRIPTION("Monitor both IPv4 and IPv6 network traffic");
MODULE_VERSION("0.01");

static struct nf_hook_ops nfho_ipv4_in;
static struct nf_hook_ops nfho_ipv6_in;

// IPv4 packet hook
static unsigned int hook_func_ipv4(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *ip_header;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    printk(KERN_INFO "[net_monitor] IPv4 SRC: %pI4 DST: %pI4 PROTO: %u\n",
           &ip_header->saddr, &ip_header->daddr, ip_header->protocol);

    return NF_ACCEPT;
}

// IPv6 packet hook
static unsigned int hook_func_ipv6(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct ipv6hdr *ipv6_header;

    if (!skb)
        return NF_ACCEPT;

    ipv6_header = ipv6_hdr(skb);
    if (!ipv6_header)
        return NF_ACCEPT;

    printk(KERN_INFO "[net_monitor] IPv6 SRC: %pI6c DST: %pI6c NXT_HDR: %u\n",
           &ipv6_header->saddr, &ipv6_header->daddr, ipv6_header->nexthdr);

    return NF_ACCEPT;
}

static int __init net_monitor_init(void)
{
    // IPv4 hook
    nfho_ipv4_in.hook = hook_func_ipv4;
    nfho_ipv4_in.hooknum = NF_INET_PRE_ROUTING;
    nfho_ipv4_in.pf = PF_INET;
    nfho_ipv4_in.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_ipv4_in);

    // IPv6 hook
    nfho_ipv6_in.hook = hook_func_ipv6;
    nfho_ipv6_in.hooknum = NF_INET_PRE_ROUTING;
    nfho_ipv6_in.pf = PF_INET6;
    nfho_ipv6_in.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_ipv6_in);

    printk(KERN_INFO "[net_monitor] Module loaded. Monitoring IPv4 and IPv6 packets.\n");
    return 0;
}

static void __exit net_monitor_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho_ipv4_in);
    nf_unregister_net_hook(&init_net, &nfho_ipv6_in);
    printk(KERN_INFO "[net_monitor] Module unloaded.\n");
}

module_init(net_monitor_init);
module_exit(net_monitor_exit);
