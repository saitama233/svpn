#ifndef _SVPN_CONNTRACK_H
#define _SVPN_CONNTRACK_H

#include "svpn_kernel.h"

#define xconn_get nf_ct_get
typedef struct nf_conn xconn;

#define tuple_get_l3num(tuple) (tuple)->src.l3num /* 第三层协议 */
#define tuple_get_l4num(tuple) (tuple)->dst.protonum /* 第四层协议 */
#define tuple_get_dip(tuple) (tuple)->dst.u3.ip
#define tuple_get_dport(tuple) (tuple)->dst.u.all
#define tuple_get_sip(tuple) (tuple)->src.u3.ip
#define tuple_get_sport(tuple) (tuple)->src.u.all

int get_conn_info(struct sk_buff *skb, struct svpn_tuple *tuple);

#endif
