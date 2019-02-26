#include <net/genetlink.h>
#include <linux/cache.h>
#include "netlink.h"
#include "net_device.h"
#include "dbg_print.h"
#include "session.h"
#include "svpn_kernel.h"
#include "../uapi/svpn.h"

static const struct nla_policy svpn_policy[SVPN_A_MAX + 1] = {
    [SVPN_A_IFNAME]     = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
    [SVPN_A_ENDPOINT]   = { .len = sizeof(struct nf_conntrack_man) },
    [SVPN_A_FLAGS]      = { .type = NLA_U32 },
    [SVPN_A_PEERS]      = { .type = NLA_NESTED },
};

static const struct nla_policy peer_policy[SVPNPEER_A_MAX + 1] = {
    [SVPNPEER_A_ENDPOINT]   = { .len = sizeof(struct nf_conntrack_man) },
    [SVPNPEER_A_L4NUM]      = { .type = NLA_U8 },
    [SVPNPEER_A_ENC]        = { .type = NLA_NUL_STRING, .len = CRYPTO_MAX_ALG_NAME - 1 },
    [SVPNPEER_A_KPP]        = { .type = NLA_NUL_STRING, .len = KPP_METHOD_LEN - 1 },
    [SVPNPEER_A_FWMARK]     = { .type = NLA_U32 },
    [SVPNPEER_A_CONNMODE]   = { .type = NLA_U8 },
    [SVPNPEER_A_LSUBNET]    = { .type = NLA_NESTED },
    [SVPNPEER_A_PSUBNET]    = { .type = NLA_NESTED },
};

static const struct nla_policy subnet_policy[SVPNSUBNET_A_MAX + 1] = {
    [SVPNSUBNET_A_FAMILY]   = { .type = NLA_U8 },
    [SVPNSUBNET_A_ADDR]     = { .len = sizeof(union nf_inet_addr) },
    [SVPNSUBNET_A_CIDR]     = { .type = NLA_U8 },
};


int set_session(struct svpn_instance_st *inst, struct nf_conntrack_man *localaddr, struct nlattr **attrs)
{
    struct svpn_st *svpn = get_gl_svpn();
	struct svpn_session_st *sess = NULL;
    struct svpn_crypto *crypto;
    xlog("in set_session\n");

	sess = kmem_cache_zalloc(svpn->sess_kmc, GFP_ATOMIC);
	if (!sess) {
		xlog("kmem_cache_alloc session error\n");
		return -1;
	}

	memcpy(&sess->tuple.src, localaddr, sizeof(*localaddr));
	nla_memcpy(&sess->tuple.dst, attrs[SVPNPEER_A_ENDPOINT], sizeof(sess->tuple.dst));
	sess->tuple.l4num = nla_get_u8(attrs[SVPNPEER_A_L4NUM]);
	sess->fwmark = nla_get_u32(attrs[SVPNPEER_A_FWMARK]);

    crypto = get_crypto(sess);
	nla_memcpy(get_encstr(crypto), attrs[SVPNPEER_A_ENC], CRYPTO_MAX_ALG_NAME);
	nla_memcpy(get_kppstr(crypto), attrs[SVPNPEER_A_KPP], KPP_METHOD_LEN);
    xlog("encstr is %s\n", get_encstr(crypto));

    /* fixme: 测试使用 */
    __u8 *sec = "\x45\x62\xac\x25\xf8\x28\x17\x6e"
                "\x4c\x26\x84\x14\xb5\x68\x01\x85"
                "\x25\x8e\x2a\x05\xe7\x3e\x9d\x03"
                "\xee\x5a\x83\x0c\xcc\x09\x4c\x87";
    set_sec(crypto, sec);

    if (sess_init(sess) < 0) {
        xlog("sess_init error\n");
        return -1;
    }

	xprint_sess(sess);

    svpn->sess_arr[sess->fwmark] = sess;

    /* fix me: 暂时没处理local subnet和peer subnet */

	/* insert list and hlist */
    xlog("to sess_insert_list\n");
	sess_insert_list(sess, inst);
    xlog("to sess_insert_htable\n");
	sess_insert_htable(sess);
    xlog("set_session end\n");
	
	return 0;
}

/* 通过general netlink传递不会进行大小端转换 */
static int svpn_setconf(struct sk_buff *skb, struct genl_info *info)
{
    int ret;
    __u32 flags = 0;
    struct svpn_st *svpn = get_gl_svpn();
    struct svpn_instance_st *inst = NULL;
    char ifname[IFNAMSIZ] = {0};
    struct nf_conntrack_man localaddr;

    ret = -EPERM;
    xlog("IFNAMSIZ is %d\n", IFNAMSIZ);
    xlog("strlen(nla_data(info->attrs[SVPN_A_IFNAME])) is %zu\n", strlen(nla_data(info->attrs[SVPN_A_IFNAME])));
    nla_memcpy(ifname, info->attrs[SVPN_A_IFNAME], IFNAMSIZ);
    if (!strlen(ifname)) {
        xlog("ifname empty\n");
        goto out;
    }
    xlog("ifname is %s, ifname_len is %zu\n", ifname, strlen(ifname));
    /* 判断SVPN_A_IFNAME是否已经存在，存在则修改，不存在则新建 */
    inst = inst_find_htable(ifname);
	inst = NULL;
	inst = inst_find_list(ifname);

#define SVPN_MODIFY 0x0002
#define SVPN_CREATE 0x0001
    if (inst) {
        flags |= SVPN_MODIFY;
    } else {
        xlog("instance need to create\n");
        flags |= SVPN_CREATE;
    }

    if (flags & SVPN_MODIFY) {
        /* fixme: 删除该inst下所有的session，删除相关路由和策略路由 */
    }
    if (flags & SVPN_CREATE) {
        inst = kmem_cache_zalloc(svpn->inst_kmc, GFP_ATOMIC);
        if (!inst) {
            xlog("kmem_cache_alloc inst error\n");
            return ret;
        }
        INIT_LIST_HEAD(&inst->sess_list);
        xlog("kmem_cache_alloc inst ok\n");
        inst->dev = create_netdev(ifname);
        xlog("create_netdev(ifname) ok\n");
        inst_insert_htable(inst);
		inst_insert_list(inst);
    }
    xlog("sizeof(struct nf_conntrack_man) is %lu\n", sizeof(struct nf_conntrack_man));
    xlog("nla_len(info->attrs[SVPN_A_ENDPOINT]) is %d\n", nla_len(info->attrs[SVPN_A_ENDPOINT]));
    /* nla_memcpy类似于memcpy, 但对长度的处理更安全些 */
    nla_memcpy(&localaddr, info->attrs[SVPN_A_ENDPOINT], sizeof(localaddr));
    xprint_ip("localaddr: ", &localaddr, 0);

	struct nlattr *attr, *peer[SVPNPEER_A_MAX + 1];
	int rem;
    nla_for_each_nested(attr, info->attrs[SVPN_A_PEERS], rem) {
        xlog("in nla_for_each_nested\n");
        /* fixme: ret = nla_parse_nested(peer, SVPNPEER_A_MAX, attr, peer_policy, NULL) */
        ret = nla_parse_nested(peer, SVPNPEER_A_MAX, attr, 0, NULL);
        if (ret < 0) {
            xlog("nla_parse_nested error\n");
            goto out;
        }
        ret = set_session(inst, &localaddr, peer);
        if (ret < 0) {
            xlog("set_session error\n");
            goto out;
        }
    }

    ret = 0;
out:
    xlog("svpn_setconf end\n");
    return ret;
}

struct genl_ops genl_ops[] = {
    {
        .cmd = SVPN_CMD_SETCONF,
        .doit = svpn_setconf,
        .policy = svpn_policy,
        .flags = GENL_UNS_ADMIN_PERM
    }
};

static struct genl_family genl_family
#ifndef COMPAT_CANNOT_USE_GENL_NOPS
__ro_after_init = {
    .ops = genl_ops,
    .n_ops = ARRAY_SIZE(genl_ops),
#else
= { 
#endif
    .name = SVPN_GENL_NAME,
    .version = SVPN_GENL_VERSION,
    .maxattr = SVPN_A_MAX,
    .module = THIS_MODULE,
    .netnsok = true
};

int __init svpn_genetlink_init(void)
{
    return genl_register_family(&genl_family);
}

void __exit svpn_genetlink_uninit(void)
{
    genl_unregister_family(&genl_family);
}

