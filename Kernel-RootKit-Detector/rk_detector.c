#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/un.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Richard Callaby");
MODULE_DESCRIPTION("Unified Rootkit & LKM Backdoor Detector");
MODULE_VERSION("0.01");

#define PROC_NAME "rootkit_report"
#define SYSCALL_COUNT 5

// ---- Syscall Hook Detection ---- //
static const char *monitored_syscalls[SYSCALL_COUNT] = {
    "sys_read", "sys_write", "sys_open", "sys_kill", "sys_getdents"
};

static unsigned long *get_syscall_table(void) {
    return (unsigned long *)kallsyms_lookup_name("sys_call_table");
}

static unsigned long get_original_syscall(const char *name) {
    return kallsyms_lookup_name(name);
}

static void detect_syscall_hooks(struct seq_file *m) {
    unsigned long *table = get_syscall_table();
    int i;
    if (!table) {
        seq_printf(m, "[!] Cannot locate sys_call_table.\n");
        return;
    }

    for (i = 0; i < SYSCALL_COUNT; i++) {
        unsigned long real = get_original_syscall(monitored_syscalls[i]);
        unsigned long actual = table[__NR_read + i];

        if (real && actual && real != actual) {
            seq_printf(m, "[!] Hooked syscall: %s\n", monitored_syscalls[i]);
            seq_printf(m, "    Expected: %px | Found: %px\n", (void *)real, (void *)actual);
        }
    }
}

// ---- Hidden Module Detection ---- //
static void detect_hidden_modules(struct seq_file *m) {
    struct list_head *mod_list = (struct list_head *)kallsyms_lookup_name("modules");
    struct module *mod;

    if (!mod_list) {
        seq_printf(m, "[!] Cannot access module list.\n");
        return;
    }

    list_for_each_entry(mod, mod_list, list) {
        if (mod->name && (mod->list.next == NULL || mod->list.prev == NULL)) {
            seq_printf(m, "[!] Possibly hidden module: %s\n", mod->name);
        }
    }
}

// ---- Hidden Process Detection ---- //
static void detect_hidden_processes(struct seq_file *m) {
    struct task_struct *task;

    for_each_process(task) {
        if (task->pid <= 0 || !task->comm)
            continue;

        struct file *exe_file = NULL;
        char *path = NULL;
        char *buf = NULL;

        exe_file = task->mm ? task->mm->exe_file : NULL;
        if (exe_file) {
            buf = (char *)__get_free_page(GFP_TEMPORARY);
            if (!buf) continue;

            path = d_path(&exe_file->f_path, buf, PAGE_SIZE);
            if (!IS_ERR(path)) {
                seq_printf(m, "PID: %d | Name: %s | Path: %s\n", task->pid, task->comm, path);
            }
            free_page((unsigned long)buf);
        } else {
            seq_printf(m, "PID: %d | Name: %s | Executable path unavailable\n", task->pid, task->comm);
        }
    }
}

// ---- LKM Backdoor Detection (Socket-based) ---- //
static void detect_lkm_backdoor_sockets(struct seq_file *m) {
    struct sock *sk;
    struct inet_hashinfo *tcp_hashinfo;
    struct hlist_nulls_node *node;
    int i;

    tcp_hashinfo = (struct inet_hashinfo *)kallsyms_lookup_name("tcp_hashinfo");
    if (!tcp_hashinfo) {
        seq_printf(m, "[!] Could not locate tcp_hashinfo\n");
        return;
    }

    for (i = 0; i < tcp_hashinfo->ehash_mask + 1; i++) {
        struct hlist_nulls_head *head = &tcp_hashinfo->ehash[i].chain;
        hlist_nulls_for_each_entry(sk, node, head, __sk_common.skc_nulls_node) {
            if (sk->sk_state == TCP_LISTEN && !sk->sk_socket) {
                seq_printf(m, "[!] Suspicious listening socket with no socket file at port %u\n",
                           ntohs(inet_sk(sk)->inet_sport));
            }
        }
    }
}

// ---- /proc interface ---- //
static int rk_show(struct seq_file *m, void *v) {
    seq_puts(m, "\n--- Rootkit & Backdoor Detection Report ---\n");

    detect_syscall_hooks(m);
    detect_hidden_modules(m);
    detect_hidden_processes(m);
    detect_lkm_backdoor_sockets(m);

    seq_puts(m, "--- End of Report ---\n");
    return 0;
}

static int rk_open(struct inode *inode, struct file *file) {
    return single_open(file, rk_show, NULL);
}

static const struct proc_ops rk_fops = {
    .proc_open = rk_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

// ---- Init & Exit ---- //
static int __init rk_init(void) {
    proc_create(PROC_NAME, 0, NULL, &rk_fops);
    printk(KERN_INFO "[rk] Rootkit report module loaded.\n");
    return 0;
}

static void __exit rk_exit(void) {
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "[rk] Rootkit report module unloaded.\n");
}

module_init(rk_init);
module_exit(rk_exit);
