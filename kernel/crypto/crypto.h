#ifndef _SVPN_CRYPTO_H
#define _SVPN_CRYPTO_H

#include "../svpn_kernel.h"

int sess_crypto_init(struct svpn_session_st *sess);
int sess_encrypt(struct sk_buff *skb, struct svpn_session_st *sess);
int sess_decrypt(struct sk_buff *skb, struct svpn_session_st *sess);

#endif
