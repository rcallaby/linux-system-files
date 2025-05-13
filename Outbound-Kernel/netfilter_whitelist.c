#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/inet.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Richard Callaby");
MODULE_DESCRIPTION("Outbound IP Whitelist Filter");
MODULE_VERSION("1.0");

static struct nf_hook_ops nfho;

// Define whitelisted IPs in network-byte order (e.g., 192.168.1.10)
static const __be32 whitelist[] = {
    0x0A000002, // 10.0.0.2
    0xC0A8010A  // 192.168.1.10
};

static const size_t whitelist_size = sizeof(whitelist) / sizeof(whitelist[0]);

static unsigned int whitelist_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    struct iphdr *ip_header;

    // Ensure it's an IP packet
    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    // We're only concerned with outbound IPv4 packets
    if (ip_header->version != 4)
        return NF_ACCEPT;

    __be32 dest_ip = ip_header->daddr;

    // Check if destination IP is in the whitelist
    for (size_t i = 0; i < whitelist_size; ++i) {
        if (dest_ip == whitelist[i]) {
            printk(KERN_INFO "Allowed outbound IP: %pI4\n", &dest_ip);
            return NF_ACCEPT;
        }
    }

    printk(KERN_WARNING "Blocked outbound IP: %pI4\n", &dest_ip);
    return NF_DROP;
}

static int __init whitelist_init(void)
{
    nfho.hook = whitelist_hook;
    nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "IP whitelist module loaded.\n");
    return 0;
}

static void __exit whitelist_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "IP whitelist module unloaded.\n");
}

module_init(whitelist_init);
module_exit(whitelist_exit);
