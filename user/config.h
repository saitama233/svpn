#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdbool.h>
#include <sys/types.h>
#include <net/if.h> /* IFNAMSIZ */
#include <linux/netfilter.h> /* nf_inet_addr */
#include <linux/netfilter/nf_conntrack_tuple_common.h> /* nf_conntrack_man_proto */
#include "common.h"
#include "list.h"
#include "../uapi/svpn.h"

#define strcaseeq(a, b) (!strcasecmp(a, b))

enum {
    CONNECTION_PASSIVE,
    CONNECTION_ACTIVE,
};

/* The manipulable part of the tuple. */
struct nf_conntrack_man {
    union       nf_inet_addr u3;
    union       nf_conntrack_man_proto u;
    /* Layer 3 protocol */
    u_int16_t   l3num;
};

struct svpn_subnet {
    __u8    family;
    char    ipstr[64];  /* 直接使用ip route命令设置路由使用，格式为"192.168.1.0/24"，以后也可使用addr和cidr替代 */
    union   nf_inet_addr addr;
    __u8    cidr;
    struct list_head node;
};

struct svpn_peer {
    struct nf_conntrack_man addrinfo;
    __u8 l4num; 	                        /* 传输层协议：TCP or UDP */
    char enc[CRYPTO_MAX_ALG_NAME];               /* 加密协议，如gcm(aes) */
    char kpp[KPP_METHOD_LEN];               /* 秘钥交换协议: Key-agreement Protocol Primitives */
    __u32 fwmark;                           /* 给连接打标记使用，同一个主机最好不要一样，会冲突 */
    __u8 conn_mode;                         /* 由哪一端主动进行连接 */
	struct list_head node;	                /* peer_list 链表节点 */
    struct list_head local_subnet_list;     /* 本端子网列表 */
    struct list_head peer_subnet_list;      /* 对端子网列表 */
};

struct svpn_local {
    char                device_name[IFNAMSIZ];
    struct nf_conntrack_man addrinfo;
};

struct svpn_config {
    struct svpn_local   local;
	struct list_head    peer_list;	/* peer_list 链表头 */
};

struct config_ctx {
    struct svpn_config  *config;
    bool                is_local_section, is_peer_section;
};

bool config_read_init(struct config_ctx *ctx, bool append);
bool config_read_line(struct config_ctx *ctx, const char *line);
struct svpn_config *config_read_finish(struct config_ctx *ctx);

#endif
