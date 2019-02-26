#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "svpn_kernel.h"
#include "conntrack.h"
#include "manskb.h"
#include "hooks.h"

/* XXX: 以后需要将这个函数放到svpn_kernel.c里 */
int svpn_pkt_rx(struct sk_buff *skb)
{
    xlog("svpn_pkt_rx begin\n");
    struct svpn_tuple tuple;
    struct svpn_session_st *sess;
    if (get_conn_info(skb, &tuple) < 0) {
        xlog("get_conn_info error\n");
        return -1;
    }
    sess = sess_find_htable(&tuple);
    if (!sess) {
        xlog("cannot find the session, dont handle this skb\n");
        return 0;
    }
    xlog("sess->fwmark is %u\n", sess->fwmark);
	if (unlikely(sess->status < SVPN_READY)) {
		/* TODO: 进行握手处理 */
        return -1;
    } else {
		if (svpn_pophdr(skb, sess) < 0) {
			xlog("svpn_pophdr error\n");
			return -1;
		}
		xlog("svpn_pophdr ok\n");
		if (sess_decrypt(skb, sess) < 0) {
			xlog("svpn_decrypt error\n");
			return -1;
		}
        xlog("sess_decrypt ok\n");
        print_skb(skb);
	}

    return 0;
}

unsigned int spkt_inet_pre_routing(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    xlog("receive_pkt_pre_routing begin\n");
    /* print_skb(skb); */
    /* if (get_conn_info(skb)) { */
        /* xlog("get conn info error\n"); */
    /* } */
    if (svpn_pkt_rx(skb) < 0)
        return NF_ACCEPT; /* FIXME: 测试抓包用，需要改为NF_DROP */
    return NF_ACCEPT;
}

unsigned int spkt_inet_local_in(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    /* xlog("spkt_inet_local_in begin\n"); */
    return NF_ACCEPT;
}

unsigned int spkt_inet_forward(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    /* xlog("spkt_inet_forward begin\n"); */
    return NF_ACCEPT;
}

unsigned int spkt_inet_local_out(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    /* xlog("spkt_inet_local_out begin\n"); */
    /* get_conn_info(skb); */
    /* print_skb(skb); */
    return NF_ACCEPT;
}

unsigned int spkt_inet_post_routing(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    /* xlog("spkt_inet_post_routing begin\n"); */
    /* print_skb(skb); */
    return NF_ACCEPT;
}

static struct nf_hook_ops svpn_ops[] = {
    {
        .hook = spkt_inet_pre_routing,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        /* 优先级比CONNTRACK小一点，这样才能得到conntrack信息 */
        .priority = NF_IP_PRI_CONNTRACK + 1, 
    },
    {
        .hook = spkt_inet_local_in,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        /* fixme: 这里的优先级可能有误 */
        .priority = NF_IP_PRI_CONNTRACK + 1,
    },
    {
        .hook = spkt_inet_forward,
        .pf = PF_INET,
        .hooknum = NF_INET_FORWARD,
        /* fixme: 这里的优先级可能有误 */
        .priority = NF_IP_PRI_CONNTRACK + 1,
    },
    {
        .hook = spkt_inet_local_out,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        /* fixme: 这里的优先级可能有误 */
        .priority = NF_IP_PRI_CONNTRACK + 1,
    },
    {
        .hook = spkt_inet_post_routing,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,
        /* fixme: 这里的优先级可能有误 */
        .priority = NF_IP_PRI_CONNTRACK + 1,
    },
};

int __init svpn_hooks_init(void)
{
    return nf_register_hooks(svpn_ops, ARRAY_SIZE(svpn_ops));
}

void __exit svpn_hooks_uninit(void)
{
    nf_unregister_hooks(svpn_ops, ARRAY_SIZE(svpn_ops));
}
