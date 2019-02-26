#include <linux/ip.h>
#include <linux/ipv6.h>
#include "conntrack.h"

static inline void svpn_dump_tuple_ip(const struct svpn_tuple *t)
{
#ifdef DEBUG
    printk("svpn_tuple %p: %u %pI4:%hu -> %pI4:%hu\n",
           t, t->l4num,
           &t->src.u3.ip, ntohs(t->src.u.all),
           &t->dst.u3.ip, ntohs(t->dst.u.all));
#endif
}

static inline void svpn_dump_tuple_ipv6(const struct svpn_tuple *t)
{
#ifdef DEBUG
    printk("svpn_tuple %p: %u %pI6 %hu -> %pI6 %hu\n",
           t, t->l4num,
           t->src.u3.all, ntohs(t->src.u.all),
           t->dst.u3.all, ntohs(t->dst.u.all));
#endif
}

static inline void xprint_svpn_tuple(struct svpn_tuple *t)
{
#if DEBUG
	if (t->src.l3num != t->dst.l3num) {
		printk("src.l3num is %u, dst.l3num is %u\n", t->src.l3num, t->dst.l3num);
		return;
	}
    switch (t->src.l3num) {
    case AF_INET:
        svpn_dump_tuple_ip(t);
        break;
    case AF_INET6:
        svpn_dump_tuple_ipv6(t);
        break;
    }
#endif
}

void xprint_tuple(enum ip_conntrack_info ctinfo, struct nf_conntrack_tuple *t)
{
#if DEBUG
    xlog("ctinfo is %d\n", ctinfo);
    nf_ct_dump_tuple(t);
#endif
}

int get_conn_info_noct(struct sk_buff *skb, struct svpn_tuple *tuple)
{
    void *nexthdr;
	if (skb->protocol == __constant_htons(ETH_P_IP)) {
    	struct iphdr *iph = ip_hdr(skb);
		tuple->src.u3.ip = iph->daddr;
		tuple->dst.u3.ip = iph->saddr;
		tuple->src.l3num = AF_INET;
		tuple->dst.l3num = AF_INET;
		tuple->l4num = iph->protocol;
        nexthdr = (void *)iph + iph->ihl * 4;
	} else if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
		/* fixme: 没有处理有多个IP头的情况, 赋值也可能有误 */
		struct ipv6hdr *ip6h = ipv6_hdr(skb);
		memcpy(&tuple->src.u3.in6.s6_addr, &ip6h->daddr.s6_addr, 16);
		memcpy(&tuple->dst.u3.in6.s6_addr, &ip6h->saddr.s6_addr, 16);
		tuple->src.l3num = AF_INET6;
		tuple->dst.l3num = AF_INET6;
		tuple->l4num = ip6h->nexthdr;
        nexthdr += sizeof(struct ipv6hdr);
	} else {
		xlog("Cannot recognise the l3num: %d\n", skb->protocol);
        return -1;
    }

    if (tuple->l4num == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)nexthdr;
        tuple->dst.u.all = tcp->source;
        tuple->src.u.all = tcp->dest;
    } else if (tuple->l4num == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)nexthdr;
        tuple->dst.u.all = udp->source;
        tuple->src.u.all = udp->dest;
    }else {
		xlog("Cannot recognise the l4num: %d\n", tuple->l4num);
		return -1;
    }

    return 0;
}

int get_conn_info(struct sk_buff *skb, struct svpn_tuple *tuple)
{
    xconn *ct;
    enum ip_conntrack_info ctinfo;
    int ctdir;

    ct = xconn_get(skb, &ctinfo);
    if (!ct) {
        xlog("Cannot find ctinfo for this skb\n");
        if (get_conn_info_noct(skb, tuple) < 0) {
			xlog("get_conn_info_noct error\n");
			return -1;
		}
    } else {
        ctdir = CTINFO2DIR(ctinfo);
		struct nf_conntrack_tuple *ct_tuple = &ct->tuplehash[ctdir].tuple;
        xprint_tuple(ctinfo, ct_tuple);
		memcpy(&tuple->dst, &ct_tuple->src, sizeof(tuple->dst));
		memcpy(&tuple->src.u3, &ct_tuple->dst.u3, sizeof(tuple->src.u3));
		tuple->src.u.all = tuple_get_dport(ct_tuple);
		tuple->src.l3num = tuple_get_l3num(ct_tuple);
		tuple->l4num = tuple_get_l4num(ct_tuple);
    }
    xprint_svpn_tuple(tuple);
    return 0;
}
