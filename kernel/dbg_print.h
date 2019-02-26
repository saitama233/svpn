#ifndef _DBG_PRINT_H
#define _DBG_PRINT_H

#include "svpn_kernel.h"

#undef pr_fmt
#define pr_fmt(fmt) \
    "svpn [%s:%d] " fmt, __func__, __LINE__
#if DEBUG
# define xlog(fmt, ...) pr_debug(fmt, ##__VA_ARGS__)
#else
# define xlog(fmt, ...) pr_warning(fmt, ##__VA_ARGS__) 
#endif

/* 下面两行可以使用%pM代替 */
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]
/* 下面四行可以使用%pI4代替，使用前需要将IP转换为网络字节序 */
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], ((unsigned char *)&addr)[3]

void xprint_ip(u8 *prompt, struct nf_conntrack_man *addr, u8 l4num);
void xprint_sess(struct svpn_session_st *sess);
void print_skb(struct sk_buff *skb);
void hexdump(unsigned char *buf, unsigned int len);

#endif
