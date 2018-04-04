#include <asm/io.h>
#include <asm/irq.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>

#include <linux/time.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/random.h>
#include <linux/netfilter_bridge.h>
#include <linux/kernel.h>
#include <net/genetlink.h>
#include <linux/netlink.h>
#include <net/ip.h>
#include <linux/inetdevice.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#include <net/genetlink.h>

#include "up.h"

static int __init up_init(void)
{

    UP_MSG_PRINTF("up link init success.");

    return 0;
}

static void __exit up_exit(void)
{

    UP_MSG_PRINTF("exit success.");

    return;
}

module_init(up_init);
module_exit(up_exit);

MODULE_AUTHOR("lyj051031448@163.com");
MODULE_VERSION("V0.1");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dns_l2");

