#include <net/ip.h> /* IP_DF */
#include <net/tcp.h> /* tcp_v4_check */
#include <net/route.h>
#include "manskb.h"

struct l3_suite {
    unsigned int l3len;
    int (*l3_pushhdr_cb)(struct sk_buff *skb, struct svpn_session_st *sess);
    int (*l3_pophdr_cb)(struct sk_buff *skb, struct svpn_session_st *sess);
    int (*reset_rt_cb)(struct sk_buff *skb, struct svpn_session_st *sess);
};

struct l4_suite {
    unsigned int l4len;
    int (*l4_pushhdr_cb)(struct sk_buff *skb, struct svpn_session_st *sess);
    int (*l4_pophdr_cb)(struct sk_buff *skb, struct svpn_session_st *sess);
};

extern const struct l3_suite l3_suites[];
extern const struct l4_suite l4_suites[];

int l4_push_tcphdr(struct sk_buff *skb, struct svpn_session_st *sess)
{
	struct svpn_config *config = get_config(sess);
	struct svpn_tuple *tuple = get_tuple(sess);
	struct tcphdr *th = NULL;
    int l4len = l4_suites[get_l4ctl(config)].l4len;
    xlog("in l4_push_tcphdr\n");
	
	skb_push(skb, l4len); /* skb_push已经更新了skb->len */
	skb_reset_transport_header(skb);
	th = tcp_hdr(skb);

	memset(th, 0, sizeof(struct tcphdr));
	th->source = get_src_port(tuple);
	th->dest = get_dst_port(tuple);
	/* fixme: 暂时seq和ack_seq使用随机数 */
	get_random_bytes(&th->seq, sizeof(th->seq));
    th->seq = htons(th->seq);
	get_random_bytes(&th->ack_seq, sizeof(th->ack_seq));
    th->ack_seq = htons(th->ack_seq);
    xlog("th->seq is %u, th->ack_seq is %u\n", ntohs(th->seq), ntohs(th->ack_seq));
	th->doff = 5; /* 没有选项 */
	th->window = __constant_htons(65535);
	/* fixme: 校验值以及csum的值可能不对 */
	th->check = 0;
    /* 此时skb->len相当于tcplen */
	skb->csum = csum_partial(skb_transport_header(skb), skb->len, 0);
	tcp_v4_check(skb->len, get_saddr_v4(tuple), get_daddr_v4(tuple), skb->csum);
	skb->ip_summed = CHECKSUM_NONE;

	return 0;
}
int l4_pop_tcphdr(struct sk_buff *skb, struct svpn_session_st *sess) 
{
    struct svpn_config *config = get_config(sess);
    int l4len = l4_suites[get_l4ctl(config)].l4len;
    xlog("l4_pop_tcphdr begin\n");

    /* 不确定是否该在这里reset */
    skb_reset_transport_header(skb);
    /* TODO: 可以进行一些处理，这里是否需要处理校验码 */
    skb_pull(skb, l4len);

    return 0; 
}

int l4_push_udphdr(struct sk_buff *skb, struct svpn_session_st *sess) { return 0; }
int l4_pop_udphdr(struct sk_buff *skb, struct svpn_session_st *sess) { return 0; }

int l3_push_iphdr(struct sk_buff *skb, struct svpn_session_st *sess)
{
	struct svpn_config *config = get_config(sess);
	struct svpn_tuple *tuple = get_tuple(sess);
	struct iphdr *iph = NULL;
    int l3len = l3_suites[get_l3ctl(config)].l3len;
    xlog("in l3_push_iphdr\n");

	skb_push(skb, l3len);
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	memset(iph, 0, sizeof(struct iphdr));

	iph->version    =   4;
	iph->ihl    	=   5; /* sizeof(struct iphdr) >> 2 */
	iph->tos 		= 	0;
	iph->tot_len	= 	htons(skb->len);
	iph->id 		= 	get_seq_no(config);
	iph->frag_off   =   __constant_htons(IP_DF); /* fixme: 这里是否需要进行大小端转换，因为frag_off类型是__be16 */
	iph->saddr  	=   get_saddr_v4(tuple);
	iph->daddr  	=   get_daddr_v4(tuple);
	iph->ttl    	=   255;
	iph->protocol	= 	get_l4num(tuple);
	/* 必须计算校验码，否则rt->dst.output无法成功发包 */
	iph->check 		= 	0;
    iph->check 		= 	ip_fast_csum((unsigned char *)iph, iph->ihl);

    /* fixme: 这里不确定是否该赋值为ETH_P_IP, 还是IPPROTO_IP */
	skb->protocol = __constant_htons(ETH_P_IP);

	return 0;
}
int l3_pop_iphdr(struct sk_buff *skb, struct svpn_session_st *sess) 
{
    struct svpn_config *config = get_config(sess);
    int l3len = l3_suites[get_l3ctl(config)].l3len;
    xlog("l3_pop_iphdr begin\n");

    /* 不确定是否该在这里reset */
    skb_reset_network_header(skb);
    /* TODO: 没有验证校验码 */
    skb_pull(skb, l3len);

    return 0; 
}

int l3_push_ipv6hdr(struct sk_buff *skb, struct svpn_session_st *sess) { return 0; }
int l3_pop_ipv6hdr(struct sk_buff *skb, struct svpn_session_st *sess) { return 0; }

int reset_rt_v4(struct sk_buff *skb, struct svpn_session_st *sess)
{
	struct svpn_tuple *tuple = get_tuple(sess);
	struct rtable *rt;
	struct flowi fl;
    xlog("in reset_rt_v4\n");
	
	memset(&fl, 0, sizeof(fl)); /* 需要清空，否则ip_route_output_key会报错 */
	skb_dst_drop(skb);
	fl.u.ip4.saddr = get_saddr_v4(tuple);
	fl.u.ip4.daddr = get_daddr_v4(tuple);
	rt = ip_route_output_key(&init_net, 
        	(struct flowi4 *)&(fl.u.ip4));
	if (IS_ERR(rt)) {
    	/* fixme: 没有正确处理该错误 */
    	xlog("ip_route_output_key error\n");
    	return -1;
	}
	skb_dst_set(skb, (struct dst_entry *)rt);
	skb->dev = skb_dst(skb)->dev;
    xlog("skb->dev->name is %s\n", skb->dev->name);
	rt->dst.output(dev_net(skb->dev), skb->sk, skb);

	return 0;
}

int reset_rt_v6(struct sk_buff *skb, struct svpn_session_st *sess) { return 0; }

int svpn_pushhdr(struct sk_buff *skb, struct svpn_session_st *sess)
{
    struct svpn_config *config = get_config(sess);
	const struct l3_suite *l3ctl = &l3_suites[get_l3ctl(config)];
	const struct l4_suite *l4ctl = &l4_suites[get_l4ctl(config)];
    xlog("in svpn_pushhdr\n");
    xlog("before svpn_pushhdr: skb->len is %u\n", skb->len);

    if (skb_cow_head(skb, l3ctl->l3len + l4ctl->l4len) < 0) { /* 确保headroom有足够的空间供skb_push使用 */
        xlog("skb_cow_head error\n");
        return -1;
    }
    xlog("l3len is %u, l4len is %u\n", l3ctl->l3len, l4ctl->l4len);
    if (l4ctl->l4_pushhdr_cb(skb, sess) < 0) {
        xlog("l4ctl->l4_pushhdr_cb error\n");
        return -1;
    }
    if (l3ctl->l3_pushhdr_cb(skb, sess) < 0) {
        xlog("l3ctl->l3_pushhdr_cb error\n");
        return -1;
    }
    /* 重置skb->mac_header，以便可以正确使用print_skb打印 */
    skb->mac_header = (typeof(skb->mac_header))~0U;
    print_skb(skb);
	
    return 0;
}

int svpn_pophdr(struct sk_buff *skb, struct svpn_session_st *sess)
{
    struct svpn_config *config = get_config(sess);
	const struct l3_suite *l3ctl = &l3_suites[get_l3ctl(config)];
	const struct l4_suite *l4ctl = &l4_suites[get_l4ctl(config)];
    xlog("in svpn_pophdr\n");

    xlog("before svpn_pophdr: skb->len is %u\n", skb->len);
    if (l3ctl->l3_pophdr_cb(skb, sess) < 0) {
        xlog("l3ctl->l3_pophdr_cb error\n");
        return -1;
    }
    if (l4ctl->l4_pophdr_cb(skb, sess) < 0) {
        xlog("l4ctl->l4_pophdr_cb error\n");
        return -1;
    }
    skb_reset_network_header(skb); /* 重置network_header头, 否则network_header指向不对,print_skb会出错 */
    skb->mac_header = (typeof(skb->mac_header))~0U; /* print_skb使用，否则会出现错误 */
    xlog("after svpn_pophdr: skb->len is %u\n", skb->len);
    return 0;
}

int svpn_reset_rt(struct sk_buff *skb, struct svpn_session_st *sess)
{
    struct svpn_config *config = get_config(sess);
    const struct l3_suite *l3ctl = &l3_suites[get_l3ctl(config)];

	if (l3ctl->reset_rt_cb(skb, sess) < 0) {
        xlog("reset_rt_cb error\n");
		return -1;
	}
	return 0;
}

const struct l3_suite l3_suites[] = {
	[IPV4_SUITE] = {
		.l3len = sizeof(struct iphdr),
		.l3_pushhdr_cb = l3_push_iphdr,
		.l3_pophdr_cb = l3_pop_iphdr,
		.reset_rt_cb = reset_rt_v4,
	},
	[IPV6_SUITE] = {
		.l3len = sizeof(struct ipv6hdr),
		.l3_pushhdr_cb = l3_push_ipv6hdr,
		.l3_pophdr_cb = l3_pop_ipv6hdr,
		.reset_rt_cb = reset_rt_v6,
	},
};

const struct l4_suite l4_suites[] = {
	[TCP_SUITE] = {
		.l4len = sizeof(struct tcphdr),
		.l4_pushhdr_cb = l4_push_tcphdr,
		.l4_pophdr_cb = l4_pop_tcphdr,
	},
	[UDP_SUITE] = {
		.l4len = sizeof(struct udphdr),
		.l4_pushhdr_cb = l4_push_udphdr,
		.l4_pophdr_cb = l4_pop_udphdr,
	},
};

