#ifndef _SVPN_HELP_H
#define _SVPN_HELP_H

#include "svpn_kernel.h"

static inline struct svpn_config *get_config(struct svpn_session_st *sess)
{
    return &sess->config;
}

static inline __be32 get_seq_no(struct svpn_config *config)
{
	return config->seq_no;
}

static inline __u8 get_l3ctl(struct svpn_config *config)
{
    return config->l3ctl;
}

static inline __u8 get_l4ctl(struct svpn_config *config)
{
    return config->l4ctl;
}

static inline struct svpn_tuple *get_tuple(struct svpn_session_st *sess)
{
    return &sess->tuple;
}

static inline __be32 get_src_port(struct svpn_tuple *tuple)
{
	return tuple->src.u.all;
}

static inline __be32 get_dst_port(struct svpn_tuple *tuple)
{
	return tuple->dst.u.all;
}

static inline __be32 get_saddr_v4(struct svpn_tuple *tuple)
{
	return tuple->src.u3.ip;
}

static inline __be32 get_daddr_v4(struct svpn_tuple *tuple)
{
	return tuple->dst.u3.ip;
}

static inline __u8 get_l4num(struct svpn_tuple *tuple)
{
	return tuple->l4num;
}

static inline struct svpn_crypto *get_crypto(struct svpn_session_st *sess)
{
    return &sess->crypto;
}

static inline __u8 *get_sec(struct svpn_crypto *crypto)
{
    return crypto->sec;
}

static inline void set_sec(struct svpn_crypto *crypto, const char *sec)
{
    strncpy(crypto->sec, sec, 256);
    crypto->seclen = strlen(sec);
}

static inline int get_seclen(struct svpn_crypto *crypto)
{
    return crypto->seclen;
}

static inline __u32 get_encid(struct svpn_crypto *crypto)
{
    return crypto->encid;
}

static inline void set_encid(struct svpn_crypto *crypto, __u32 encid)
{
    crypto->encid = encid;
}

static inline __u8 *get_encstr(struct svpn_crypto *crypto)
{
    return crypto->encstr;
}

static inline __u8 *get_kppstr(struct svpn_crypto *crypto)
{
    return crypto->kppstr;
}

static inline __u8 get_authsize(struct svpn_crypto *crypto)
{
    return crypto->authsize;
}

static inline void set_authsize(struct svpn_crypto *crypto, __u8 authsize)
{
    crypto->authsize = authsize;
}

static inline struct crypto_aead *get_aead(struct svpn_crypto *crypto)
{
    return crypto->aead;
}

#endif
