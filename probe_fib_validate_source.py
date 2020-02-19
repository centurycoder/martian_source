#!/usr/bin/python
bpf_text = """
#include <linux/skbuff.h>
#include <uapi/linux/types.h>
#include <linux/sched.h>
#include <uapi/linux/if.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/net_namespace.h>
#include <net/flow.h>
#include <net/netns/ipv4.h>

struct my_data_t
{
    char devname[IFNAMSIZ];
    int ret;
};

BPF_PERF_OUTPUT(custom_event);

int probe_fib_validate_source(struct pt_regs *ctx, struct sk_buff *skb, __be32 src, __be32 dst, u8 tos, int oif, struct net_device *dev)
{
    struct my_data_t mdata = {0};

    mdata.ret = PT_REGS_RC(ctx);
    bpf_probe_read(mdata.devname, IFNAMSIZ, dev->name);

    custom_event.perf_submit(ctx, &mdata, sizeof(mdata));
    return 0;
}


"""

from bcc import BPF
import ctypes as ct

class MyData(ct.Structure):
    _fields_ = [
        ("devname", ct.c_char * 16),
        ("ret", ct.c_int),
    ]

bpf = BPF(text=bpf_text)

def print_event (cpu, data, size):
    #event = b["probe_icmp_events"].event(data)
    event = ct.cast(data, ct.POINTER(MyData)).contents
    print("%s %d" % (event.devname, event.ret))

bpf.attach_kprobe(event="fib_validate_source",fn_name="probe_fib_validate_source")
bpf.attach_kretprobe(event="fib_validate_source",fn_name="probe_fib_validate_source")

bpf["custom_event"].open_perf_buffer(print_event)
while 1:
    try:
        bpf.kprobe_poll()
    except KeyboardInterrupt:
        exit()