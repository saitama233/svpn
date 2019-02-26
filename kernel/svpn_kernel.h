#ifndef _SVPN_KERNEL_H
#define _SVPN_KERNEL_H

#include <linux/jhash.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack_core.h>
#include "../uapi/svpn.h"

/* extern struct svpn_st *gl_svpn; */
struct svpn_st *get_gl_svpn(void);

enum l3_suite_num {
    IPV4_SUITE,
    IPV6_SUITE,
};

enum l4_suite_num {
    TCP_SUITE,
    UDP_SUITE,
};

enum svpn_status {
    SVPN_INVALID,
    SVPN_HANDSHAKE_INITIATION,
    SVPN_HANDSHAKE_RESPONSE,
    SVPN_HANDSHAKE_OK,
    SVPN_READY,
    SVPN_DATA,
    SVPN_KEEPALIVE,
};

struct svpn_tuple {
	struct nf_conntrack_man src;
	struct nf_conntrack_man dst;
	u_int8_t l4num; /* 和nf_conntrack_tuple的t->dst.protonum一致, IPPROTO_TCP或IPPROTO_UDP */
};

struct svpn_session_st;
struct svpn_config {
    __be32      seq_no; /* Sequence number，序列号，防止重放攻击，每发送一个包便递增一个 */
    __u8        l3ctl;
    __u8        l4ctl;
};

#define DEFAULT_AUTHSIZE 8
struct svpn_crypto {
    struct crypto_aead  *aead;
    __u8    authsize;    
    __u8    encstr[CRYPTO_MAX_ALG_NAME]; /* 加密算法: AES, RC5, base64等 */
    __u8    kppstr[KPP_METHOD_LEN]; /* 秘钥协商算法 */
    __u32   encid;
    __u32   kppid;
    __u8    sec[256];
    int     seclen;
    __u8    pub[256];
};

struct svpn_st {
    struct svpn_session_st  **sess_arr; /* 使用mark做索引的session数组, 不好的设计，但暂时想不到更好办法 */

    /* fixme: inst_htable和inst_kmc都没必要使用，可以删了 */
	struct hlist_head       *inst_htable; /* instance hash table, 使用dev的ifname做hash */
	__u32                   inst_ht_size;
    struct list_head        inst_list; /* instance double-linked list, 删除使用, 使用hash table删除比较耗时, 空间换时间 */
	spinlock_t              inst_lock;
	struct kmem_cache       *inst_kmc;

    struct hlist_head       *sess_htable; /* session hash table, 使用本端IP和本端端口进行hash, 主要用于解密 */
    __u32                   sess_ht_size;
    spinlock_t              sess_lock;
    struct kmem_cache       *sess_kmc;
};

struct svpn_instance_st { /* 每个网卡建立一个instance */
    struct hlist_node   hlist_node;
    struct list_head    list_node;
    struct net_device   *dev;
    struct list_head    sess_list;
};

struct svpn_session_st { /* 每个peer建立一个session */
	struct list_head    list_node;
    struct hlist_node   hlist_node;
	__u32 				fwmark;
    struct svpn_tuple   tuple;
    struct svpn_config  config; /* 该session的配置 */
    struct svpn_crypto  crypto;
	
    enum svpn_status    status; /* svpn状态, 是否已经握手完成 */
};

struct svpn_header_st {
	__u32 	len;		/* 头部长度, 因为认证数据是可变的 */
    __be32  seq_no;      /* Sequence number，序列号，防止重放攻击 */
    __u8    auth_data[0];  /* 摘要值， Variable len but >=8. Mind the 64 bit alignment! */
};

/* 以下几个文件全是和svpn_kernel.h有相互包含关系, 设计不好导致?? */
#include "svpn_help.h"
#include "crypto/crypto.h"

/* dbg_print.h 不能放在前面，因为使用了 svpn_session_st/svpn_config/svpn_tuple等结构 */
#include "dbg_print.h"

static inline struct hlist_head* get_inst_head(const u8 *ifname, u32 len)
{
	struct svpn_st *svpn = get_gl_svpn();
	u32 hash = jhash(ifname, len, 0);

	return &svpn->inst_htable[hash & (svpn->inst_ht_size - 1)];
}

static inline struct svpn_instance_st *inst_find_htable(const u8 *ifname)
{
	struct hlist_head *hlist_head = get_inst_head(ifname, strlen(ifname));
	struct svpn_instance_st *inst = NULL;

	hlist_for_each_entry(inst, hlist_head, hlist_node) {
		if (!strcmp(inst->dev->name, ifname))
			return inst;
	}
	return NULL;
}

static inline struct svpn_instance_st *inst_find_list(const u8 *ifname)
{
    struct svpn_st *svpn = get_gl_svpn();
    struct svpn_instance_st *inst;
    list_for_each_entry(inst, &svpn->inst_list, list_node) {
        if (!strcmp(inst->dev->name, ifname))
            return inst;
    }
    return NULL;
}

static inline void inst_insert_htable(struct svpn_instance_st *inst)
{
	hlist_add_head(&inst->hlist_node, get_inst_head(inst->dev->name, strlen(inst->dev->name)));
}

static inline void inst_insert_list(struct svpn_instance_st *inst)
{
    struct svpn_st *svpn = get_gl_svpn();
    list_add_tail(&inst->list_node, &svpn->inst_list);
}

static inline struct hlist_head* get_sess_head(const u8 *str, u32 len)
{
    struct svpn_st *svpn = get_gl_svpn();
    u32 hash = jhash(str, len, 0);

    return &svpn->sess_htable[hash & (svpn->sess_ht_size - 1)];
}

static inline void sess_insert_htable(struct svpn_session_st *sess)
{
    hlist_add_head(&sess->hlist_node, get_sess_head((u8 *)&sess->tuple.src, sizeof(sess->tuple.src)));
}

static inline struct svpn_session_st *sess_find_htable(struct svpn_tuple *tuple)
{
	struct hlist_head *hlist_head = get_sess_head((u8 *)&tuple->src, sizeof(tuple->src));
	struct svpn_session_st *sess;

    hlist_for_each_entry(sess, hlist_head, hlist_node) {
        if (!memcmp(&tuple->src, &sess->tuple.src, sizeof(struct nf_conntrack_man)))
            return sess;
    }
    return NULL;
}

static inline void sess_insert_list(struct svpn_session_st *sess, struct svpn_instance_st *inst)
{
    list_add_tail(&sess->list_node, &inst->sess_list);
}

#endif
