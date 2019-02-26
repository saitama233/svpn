#ifndef _SVPN_MANSKB_H
#define _SVPN_MANSKB_H

#include "svpn_kernel.h"

int svpn_pushhdr(struct sk_buff *skb, struct svpn_session_st *sess);
int svpn_pophdr(struct sk_buff *skb, struct svpn_session_st *sess);
int svpn_reset_rt(struct sk_buff *skb, struct svpn_session_st *sess);

#endif

