from bcc import BPF

bpf_source = """
#include <linux/skbuff.h>
#include <uapi/linux/types.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/net_namespace.h>
#include <net/flow.h>
#include <net/netns/ipv4.h>

int kprobe__fib_validate_source(struct pt_regs *ctx, struct sk_buff *skb, __be32 src, __be32 dst, u8 tos, int oif, struct net_device *dev)
{
    int ret = PT_REGS_RC(ctx);
    bpf_trace_printk("device=%s\\n", dev->name);
    return 0;
}
int kretprobe__fib_validate_source(struct pt_regs *ctx, struct sk_buff *skb, __be32 src, __be32 dst, u8 tos, int oif, struct net_device *dev)
{
    int ret = PT_REGS_RC(ctx);
    bpf_trace_printk("ret=%d\\n", ret);
    return 0;
}
"""

bpf = BPF(text = bpf_source)
bpf.trace_print()