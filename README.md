# 为什么tunl0不配置IP时会触发”martian source"报错

## 源码初步分析

1 我们按照 "martian source"在linux内核当中检索，发现该日志错误是在ip_handle_martian_source()这个函数中打印的

```C
/* https://github.com/torvalds/linux/blob/master/net/ipv4/route.c */
static void ip_handle_martian_source(）
{
    ...
    pr_warn("martian source %pI4 from %pI4, on dev %s\n",&daddr, &saddrdev->name);
    ...
}
```

2 来看看是哪里调用了ip_handle_martian_source()函数？ 我们发现有2处调用，一处是在__mkroute_input()，一处是在ip_route_input_slow()函数，这两处调起ip_handle_martian_source()函数的原因是一行的，就是由于fib_validate_source这个函数返回了非0，如下代码所示

```C
err = fib_validate_source(skb, saddr, daddr, tos,LOOPBACK_IFINDEX,dev, in_dev, &itag);
if (err < 0)
    goto martian_source_keep_err;
...
martian_source_keep_err:
    ip_handle_martian_source(dev, in_dev, skb, daddr, saddr);
```

3 所以我们进一步分析fib_validate_source()这个函数，看在什么情况下它会返回非0。该函数实际调用__fib_validate_source()来实现，所以继续分析后者的实现。在__fib_validate_source()函数中，有比较多的地方会返回非0，那有什么好办法知道到底是哪处返回的非0呢？一个比较好的办法就是，如果我们能够知道这个函数实际的返回值是多少，我们便可以顺藤摸瓜，找出造成非0返回的地方。

## eBPF分析

1 从Linux 3.15内核开始，Linux便支持extended BPF (Berkeley Packet Filters)这种内核调试工具，而BCC工具（<https://github.com/iovisor/bcc>）更是基于eBPF提供了更简单地创建内核trace的方法，BCC提供最常用的kprobe和kretprobe函数，让我们可以在内核函数开始或者是返回前，执行一段我们自定义的代码，从而去窥探内核状态甚至改变内核行为（例如修改内核函数返回值）。这里，我们就是准备用kretprobe函数来探测一下，看看在出现"martian source"的这种情况下，fib_validate_source()的返回值到底是多少。

- 如果内核版本较低不支持eBPF，需要先升级内核版本（centos/RHEL可以参考此文<https://www.howtoforge.com/tutorial/how-to-upgrade-kernel-in-centos-7-server/>）

- BCC的安装可以参考<https://github.com/iovisor/bcc/blob/master/INSTALL.md>，centos/RHEL可以简单地通过yum install bcc-tools安装。

2 按照BCC提供的范例（参考<https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#2-kretprobes>），我们写一段BCC代码，尝试获取fib_validate_source()的返回值

```py
# bcc_fib_validate_source.py
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
```

3 执行这段BCC代码，并在客户端执行telnet测试，就看到有如下输出，也就是说，对tunl0网卡进来的包在执行fib_validate_source时，其返回值每次都是-18。

```txt
<idle>-0     [001] d.s.  1075.756041: : device=tunl0
<idle>-0     [001] d.s.  1075.756042: : ret=-18
<idle>-0     [001] d.s.  1076.026750: : device=eth0
<idle>-0     [001] d.s.  1076.026780: : ret=0
<idle>-0     [001] d.s.  1076.757357: : device=eth0
<idle>-0     [001] d.s.  1076.757399: : ret=0
<idle>-0     [001] d.s.  1076.757413: : device=tunl0
<idle>-0     [001] d.s.  1076.757414: : ret=-18
<idle>-0     [001] d.s.  1078.760951: : device=eth0
<idle>-0     [001] d.s.  1078.760967: : ret=0
<idle>-0     [001] d.s.  1078.760984: : device=tunl0
<idle>-0     [001] d.s.  1078.760985: : ret=-18
```

## 源码定位

1 这时我们再回到内核源代码，看看fib_validate_source()在什么情况下会返回-18，检查所有return语句，我们发现最后，-EXDEV的值就是-18

```c
/* https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c line 412*/

e_rpf:
    return -EXDEV;
```

2 我们再找找看是何处会跳转到e_rpf:

```c
/* https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c line 404*/

last_resort:
    if (rpf)
        goto e_rpf;
```

3 我们再找找跳转到last_resort的，有2个地方：

- 如果fib_lookup返回非0

```c
/* https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c line 374*/

net = dev_net(dev);
if (fib_lookup(net, &fl4, &res))
    goto last_resort;

```

- 如果no_addr变量为true

```c
/* https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c fuction __fib_validate_source()*/

no_addr = idev->ifa_list == NULL;

if (dev_match) {
    ret = FIB_RES_NH(res).nh_scope >= RT_SCOPE_HOST;
    return ret;
}
if (no_addr)
    goto last_resort;
if (rpf == 1)
    goto e_rpf;
```

4 我们用类似的BCC代码检查fib_lookup()函数的返回值，就发现该函数返回值一直是0，也就是说，造成fib_validate_source()返回-18的代码就是由于no_addr为true，而通过检查no_addr赋值的地方，就可以知道ifa_list==NULL，也就是说当tunl0的inetdevice上没有配置IP（ifa_list是IP数据结构的list）的时候，就会被判断为no_addr。
