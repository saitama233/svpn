#include <net/ip.h>
#include "session.h"

int set_sess_l3suite(struct svpn_session_st *sess)
{
    xlog("IPPROTO_IP is %u, IPPROTO_IPV6 is %u\n", IPPROTO_IP, IPPROTO_IPV6);
    if (sess->tuple.src.l3num == AF_INET) { /* fixme: 这里或许要注意下大小端 */
        sess->config.l3ctl = IPV4_SUITE;
    } else if (sess->tuple.src.l3num == AF_INET6) {
        sess->config.l3ctl = IPV6_SUITE;
	} else {
        xlog("Cannot find l3num: %hu\n", sess->tuple.src.l3num);
        return -1;
    }
    return 0;
}

int set_sess_l4suite(struct svpn_session_st *sess)
{
    struct svpn_tuple *tuple = get_tuple(sess);
    if (get_l4num(tuple) == IPPROTO_TCP) {
        sess->config.l4ctl = TCP_SUITE;
    } else if (get_l4num(tuple) == IPPROTO_UDP) {
        sess->config.l4ctl = UDP_SUITE;
	} else {
        xlog("Cannot find l4num: %d\n", get_l4num(tuple));
        return -1;
    }
    return 0;
}

int sess_init(struct svpn_session_st *sess)
{
    /* fixme: status暂时先设置为SVPN_READY */
    sess->status = SVPN_READY;

	/* 新建session时直接给一些数据赋值，防止每次发包时都需要计算 */
    if (set_sess_l3suite(sess) < 0) {
        xlog("set_sess_l3suite error\n");
        return -1;
    }
    if (set_sess_l4suite(sess) < 0) {
        xlog("set_sess_l4suite error\n");
        return -1;
    }

    struct svpn_crypto *crypto = get_crypto(sess);
    hexdump(get_sec(crypto), get_seclen(crypto));          
    xlog("get_seclen(crypto) is %d\n", get_seclen(crypto));

    if (sess_crypto_init(sess) < 0) {
        xlog("sess_crypto_init error\n");
        return -1;
    }

    return 0;
}
