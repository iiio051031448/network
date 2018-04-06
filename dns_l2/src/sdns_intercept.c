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

typedef struct dns_flags {
#if __BYTE_ORDER__ ==__ORDER_LITTLE_ENDIAN__
    unsigned short rcode:4,
                   z:3,
                   ra:1,
                   rd:1,
                   tc:1,
                   aa:1,
                   opcode:4,
                   qr:1;
#elif __BYTE_ORDER__ ==__ORDER_BIG_ENDIAN__
    unsigned short qr:1,
                   opcode:4,
                   aa:1,
                   tc:1,
                   rd:1,
                   ra:1,
                   z:3,
                   rcode:4;
#endif
}__attribute__((packed)) DNS_FLAGS_ST;

union flags_un {
    struct dns_flags bits;
    unsigned short unit;
};

typedef struct s_dns_header
{
    unsigned short id;
    union flags_un flags;
    unsigned short qr_cnt;
    unsigned short an_cnt;
    unsigned short ns_cnt;
    unsigned short ar_cnt;
}__attribute__((packed)) S_DNS_HEADER_ST;

typedef struct dns_rrs_tag
{
    unsigned short name;
    unsigned short type;
    unsigned short class;
    /* unsigned long  ttl; 8 bit for X86_64 */
    unsigned int ttl;
    unsigned short len;
    /* unsigned long  ip; 8 bit for X86_64 */
    unsigned int ip;
}__attribute__((packed)) S_DNS_RRS_ST;

static int extract_domain_name(char *str, char *name, int maxlen)
{
    char *p = str;
    char *q = name;
    int len = 0;
    while(*p != 0 && *p < 32) p++;
    while(*p != 0 && len < maxlen){
        if(*p < 32)
            *q = '.';
        else
            *q = *p;
        len ++;
        p ++;
        q ++;
    }
    *q = 0;

    return 0;
}

static int do_dns_intercept(struct sk_buff *skb,
                            struct ethhdr *eh,
                            struct iphdr  *ih,
                            struct udphdr *uh,
                            S_DNS_HEADER_ST *dh)
{
    char *p = NULL;
    char buf[16];
    __be32 addr;
    union flags_un flags;
    S_DNS_RRS_ST *answer = NULL;

    flags.unit = ntohs(dh->flags.unit);

    flags.bits.qr = 1;
    flags.bits.aa = 1;
    flags.bits.ra = 1;
    dh->flags.unit = htons(flags.unit);

    /* answers count */
    dh->an_cnt = htons(1); 

    p = skb_put(skb, sizeof(S_DNS_RRS_ST)); /* TODO:room is enough ? */
    if (NULL == p) {
        return NF_ACCEPT;
    }

    answer = (S_DNS_RRS_ST *)((char *)p);
    answer->name = htons(0xC00C);
    answer->type = htons(0x1);
    answer->class = htons(0x1);
    answer->ttl = htonl(0x0);
    answer->len = htons(0x4);
    answer->ip = str2ip("10.2.10.46");

    uh->len = htons(ntohs(uh->len) + sizeof(S_DNS_RRS_ST));
    ih->tot_len = htons(ntohs(ih->tot_len) + sizeof(S_DNS_RRS_ST));

    /* swap dest and source port.
     * use uh->check as tmp var, so smart ! */
    uh->check = uh->source;
    uh->source = uh->dest;
    uh->dest = uh->check;
    uh->check = 0;

    /* swap dest and source ip addr */
    addr = ih->saddr;
    ih->saddr = ih->daddr;
    ih->daddr = addr;
    ih->check = 0;
    ih->id = 0;

    /* swap dest and source mac addr */
    memcpy(buf, eh->h_dest, ETH_ALEN);
    memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
    memcpy(eh->h_source, buf,ETH_ALEN);

    //TODO:udp checksum
    
    /* ip header check */
    ip_send_check(ih);
    skb_push(skb, 14); //TODO: for what?
    if (eh->h_proto == ntohs(ETH_P_8021Q)) {
        skb_push(skb, 4);
    }

    __DUMP_DATA(skb->data, skb->len);

    dev_queue_xmit(skb);

    return NF_STOLEN;
}

unsigned int sdns_skb_dns_intercept(const struct nf_hook_ops *ops, 
                                   struct sk_buff *skb,
                                   const struct net_device *in, 
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))


{ 
    int ret = NF_ACCEPT;
    struct ethhdr *eh = NULL;
    struct iphdr  *ih = NULL;
    struct udphdr *uh = NULL;
    S_DNS_HEADER_ST *dh = NULL;
    u16 dport = 0, sport = 0;
    char qr_domain[256];

    if (NULL == skb) {
        return NF_ACCEPT;
    }

    eh = eth_hdr(skb);
    if (NULL == eh) {
        return NF_ACCEPT;
    }

    if (skb->protocol == htons(ETH_P_IP)) {
        ih = ip_hdr(skb);
    }

    if (skb->protocol == htons(ETH_P_8021Q) && ih) { /* why && ih?? */
        ih = (struct iphdr *) ((u8*)ih + 4);
    }

    if (NULL == ih || ih->protocol != IPPROTO_UDP) {
        return NF_ACCEPT;
    }

    uh = (struct udphdr *)((u8*)ih +ip_hdrlen(skb));

    dport = ntohs(uh->dest);
    sport = ntohs(uh->source);

    if (dport != 53 && sport != 53) {
        return NF_ACCEPT;
    }
    UP_MSG_PRINTF("dport : %d sport : %d\n", dport, sport);

    dh = (S_DNS_HEADER_ST *)(uh + 1);

    UP_MSG_PRINTF("bits qr : [%d]", dh->flags.bits.qr);

    if (dport == 53 && dh->flags.bits.qr == 0) { /* qr->0:query, 1:response*/
        UP_MSG_PRINTF("questions cnt : [%d]", ntohs(dh->qr_cnt));
        if (ntohs(dh->qr_cnt) != 1) { /* questions should be 1 */
            return NF_ACCEPT;
        }

        UP_MSG_PRINTF("answer cnt : [%d]", ntohs(dh->an_cnt));
        if (ntohs(dh->an_cnt) != 0) { /* contain answer, may be it is not a dns packet */
            return NF_ACCEPT;
        }

        extract_domain_name((char *)(dh + 1), qr_domain, sizeof(qr_domain));
        UP_MSG_PRINTF("qr domain : [%s]", qr_domain);

        ret = do_dns_intercept(skb, eh, ih, uh, dh);
    }

    return ret;
}

static struct nf_hook_ops sdns_hooks[] = {
    {
        .owner    = THIS_MODULE,
        .hooknum  = NF_BR_PRE_ROUTING,
        .pf       = PF_BRIDGE,
        .priority = NF_BR_PRI_FIRST,
        .hook     = sdns_skb_dns_intercept,
    },
};

static int __init up_init(void)
{

    nf_register_hooks(sdns_hooks, ARRAY_SIZE(sdns_hooks));

    UP_MSG_PRINTF("up link init success.");

    return 0;
}

static void __exit up_exit(void)
{
    nf_unregister_hooks(sdns_hooks, ARRAY_SIZE(sdns_hooks));

    UP_MSG_PRINTF("exit success.");

    return;
}

module_init(up_init);
module_exit(up_exit);

MODULE_AUTHOR("lyj051031448@163.com");
MODULE_VERSION("V0.1");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("dns_l2");

