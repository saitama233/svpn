#include <net/arp.h>
#include <net/tcp.h>
#include "dbg_print.h"
#include "net_device.h"
#include "manskb.h"

netdev_tx_t svpndev_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct svpn_st *svpn = get_gl_svpn();
    struct svpn_session_st *sess = NULL;
	
    xlog("in svpndev_start_xmit\n");
    print_skb(skb);
    sess = svpn->sess_arr[skb->mark];
    xprint_sess(sess);
    if (!sess) {
        xlog("cannot find the session, mark is %u\n", skb->mark);
        return NETDEV_TX_OK;
    }
    if (sess->status < SVPN_READY) {
        xlog("sess->status error: status is %d\n", sess->status);
        return NETDEV_TX_OK;
    }
    xlog("check sess's status ok\n");

    xlog("before sess_encrypt, skb->len is %u\n", skb->len);
    if (sess_encrypt(skb, sess) < 0) {
        xlog("sess_encrypt error\n");
        return NETDEV_TX_OK;
    }
    xlog("sess_encrypt ok\n");
    xlog("after sess_encrypt, skb->len is %u\n", skb->len);

	if (svpn_pushhdr(skb, sess) < 0) {
		xlog("svpn_pushhdr error\n");
		return NETDEV_TX_OK;
	}
    xlog("svpn_pushhdr ok\n");

	if (svpn_reset_rt(skb, sess) < 0) {
		xlog("svpn_reset_rt error\n");
		return NETDEV_TX_OK;
	}
    xlog("svpn_reset_rt ok\n");

    return NETDEV_TX_OK;
}

static const struct net_device_ops wysvpn_netdev_ops = {
    .ndo_start_xmit = svpndev_start_xmit,
};

void svpndev_setup(struct net_device *dev)
{
    dev->netdev_ops = &wysvpn_netdev_ops;
    dev->type = ARPHRD_PPP;
}

struct net_device *create_netdev(char *devname)
{ 
	struct net_device *dev;
    int ret; 
    dev = alloc_netdev(sizeof(int), devname, NET_NAME_UNKNOWN, svpndev_setup);
    if (!dev) {
        goto err;
    }
 
    ret = register_netdev(dev);
    if (ret) {
        goto err;
    }
    return dev;
 
err:
    if (dev)
        free_netdev(dev);
    return NULL;
}
