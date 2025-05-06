#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/sock.h>
#include <linux/netlink.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Richard Callaby");
MODULE_DESCRIPTION("Dynamic ACL Kernel Plugin with Deletion and Netlink");
MODULE_VERSION("0.01");

#define MAX_RULES 64
#define MAX_LINE 128
#define NETLINK_USER 31

// Rule tables
static char *blocked_ips[MAX_RULES];
static int blocked_ports[MAX_RULES];
static int restricted_uids[MAX_RULES];
static int ip_count = 0, port_count = 0, uid_count = 0;

// Netfilter and procfs
static struct nf_hook_ops nfho;
static struct proc_dir_entry *proc_file;

// Netlink
static struct sock *nl_sk = NULL;
static void send_to_user(const char *msg) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int pid = 0;  // broadcast to all listeners
    int msg_size = strlen(msg);

    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) return;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    strncpy(nlmsg_data(nlh), msg, msg_size);
    netlink_broadcast(nl_sk, skb, pid, 0, GFP_KERNEL);
}

// Helpers
static void delete_ip(const char *ip) {
    int i;
    for (i = 0; i < ip_count; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) {
            kfree(blocked_ips[i]);
            blocked_ips[i] = blocked_ips[--ip_count];
            printk(KERN_INFO "[acl] Deleted IP %s\n", ip);
            return;
        }
    }
}

static void delete_port(int port) {
    int i;
    for (i = 0; i < port_count; i++) {
        if (blocked_ports[i] == port) {
            blocked_ports[i] = blocked_ports[--port_count];
            printk(KERN_INFO "[acl] Deleted Port %d\n", port);
            return;
        }
    }
}

static void delete_uid(int uid) {
    int i;
    for (i = 0; i < uid_count; i++) {
        if (restricted_uids[i] == uid) {
            restricted_uids[i] = restricted_uids[--uid_count];
            printk(KERN_INFO "[acl] Deleted UID %d\n", uid);
            return;
        }
    }
}

// Netfilter hook
static unsigned int hook_func(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    int i;
    char msg[128];

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    for (i = 0; i < ip_count; i++) {
        if (iph->daddr == in_aton(blocked_ips[i])) {
            snprintf(msg, sizeof(msg), "[ACL] Dropped IP: %pI4", &iph->daddr);
            send_to_user(msg);
            return NF_DROP;
        }
    }

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        for (i = 0; i < port_count; i++) {
            if (ntohs(tcph->dest) == blocked_ports[i]) {
                snprintf(msg, sizeof(msg), "[ACL] Dropped TCP port: %d", blocked_ports[i]);
                send_to_user(msg);
                return NF_DROP;
            }
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        for (i = 0; i < port_count; i++) {
            if (ntohs(udph->dest) == blocked_ports[i]) {
                snprintf(msg, sizeof(msg), "[ACL] Dropped UDP port: %d", blocked_ports[i]);
                send_to_user(msg);
                return NF_DROP;
            }
        }
    }

    return NF_ACCEPT;
}

// Proc interface
static ssize_t proc_write(struct file *file, const char __user *ubuf,
                          size_t count, loff_t *ppos) {
    char *buf;
    char cmd[MAX_LINE];
    int val;

    buf = kzalloc(count + 1, GFP_KERNEL);
    if (!buf) return -ENOMEM;
    if (copy_from_user(buf, ubuf, count)) {
        kfree(buf);
        return -EFAULT;
    }

    if (sscanf(buf, "block_ip %127s", cmd) == 1 && ip_count < MAX_RULES) {
        blocked_ips[ip_count++] = kstrdup(cmd, GFP_KERNEL);
    } else if (sscanf(buf, "block_port %d", &val) == 1 && port_count < MAX_RULES) {
        blocked_ports[port_count++] = val;
    } else if (sscanf(buf, "block_uid %d", &val) == 1 && uid_count < MAX_RULES) {
        restricted_uids[uid_count++] = val;
    } else if (sscanf(buf, "del_ip %127s", cmd) == 1) {
        delete_ip(cmd);
    } else if (sscanf(buf, "del_port %d", &val) == 1) {
        delete_port(val);
    } else if (sscanf(buf, "del_uid %d", &val) == 1) {
        delete_uid(val);
    }

    kfree(buf);
    return count;
}

static const struct proc_ops proc_file_ops = {
    .proc_write = proc_write,
};

// Init & exit
static int __init acl_init(void) {
    struct netlink_kernel_cfg cfg = {
        .groups = 1
    };

    nfho.hook = hook_func;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

    proc_file = proc_create("acl_config", 0666, NULL, &proc_file_ops);
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

    if (!proc_file || !nl_sk) {
        printk(KERN_ERR "[acl] Init failed.\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "[acl] Module loaded with deletion and netlink support.\n");
    return 0;
}

static void __exit acl_exit(void) {
    int i;
    nf_unregister_net_hook(&init_net, &nfho);
    proc_remove(proc_file);
    netlink_kernel_release(nl_sk);

    for (i = 0; i < ip_count; i++)
        kfree(blocked_ips[i]);

    printk(KERN_INFO "[acl] Module unloaded.\n");
}

module_init(acl_init);
module_exit(acl_exit);
