#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <arpa/inet.h> /* ntohs */
#include "mnlg.h"
#include "config.h"
#include "list.h"
#include "../uapi/svpn.h"

#ifdef __linux__
#define SOCKET_BUFFER_SIZE MNL_SOCKET_BUFFER_SIZE
#else           
#define SOCKET_BUFFER_SIZE 8192
#endif          

int user_setconf(struct svpn_config *config)
{
    dbg_lprintf("in user_setconf\n");
    struct svpn_peer *peer;
    struct svpn_subnet *lsubnet, *psubnet;
    char cmd[1024];

    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    system("echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter");
    sprintf(cmd, "ip link set %s up", config->local.device_name);
    system(cmd);
    list_for_each_entry(peer, &config->peer_list, node) {
        list_for_each_entry(lsubnet, &peer->local_subnet_list, node) {
            sprintf(cmd, "iptables -t mangle -A PREROUTING -s %s -j MARK --set-mark %d", lsubnet->ipstr, peer->fwmark);
            system(cmd);
            dbg_lprintf("cmd is %s\n", cmd);
            sprintf(cmd, "iptables -t mangle -A OUTPUT -s %s -j MARK --set-mark %d", lsubnet->ipstr, peer->fwmark);
            system(cmd);
            dbg_lprintf("cmd is %s\n", cmd);
        }
        sprintf(cmd, "ip rule add fwmark %d table %d", peer->fwmark, peer->fwmark);
        system(cmd);
        dbg_lprintf("cmd is %s\n", cmd);
        list_for_each_entry(psubnet, &peer->peer_subnet_list, node) {
            sprintf(cmd, "ip route add %s dev svpn5 table %d", psubnet->ipstr, peer->fwmark);
            system(cmd);
            dbg_lprintf("cmd is %s\n", cmd);
        }
    }
    return 0;
}

/* fixme: 有兴趣可以拆分下函数，太长了 */
int kernel_setconf(struct svpn_config *config)
{
    struct mnlg_socket *nlg;
    struct nlmsghdr *nlh;
    struct nf_conntrack_man *addrinfo;
    struct nlattr *peers_nest, *peer_nest;
    struct nlattr *lsubnets_nest, *lsubnet_nest, *psubnets_nest, *psubnet_nest;
    struct svpn_peer *peer;
	struct svpn_subnet *subnet;
	int ret = 0;
    dbg_lprintf("in kernel_setconf\n");

    nlg = mnlg_socket_open(SVPN_GENL_NAME, SVPN_GENL_VERSION);
    if (!nlg)
        return -errno;

    nlh = mnlg_msg_prepare(nlg, SVPN_CMD_SETCONF, NLM_F_REQUEST | NLM_F_ACK);

    /* set local configuration */
    /* mnl_attr_put_strz is similar to mnl_attr_put_str, but it includes the
     * NUL/zero ('\0') terminator at the end of the string.
     */
    mnl_attr_put_strz(nlh, SVPN_A_IFNAME, config->local.device_name);
    addrinfo = &config->local.addrinfo;
    mnl_attr_put(nlh, SVPN_A_ENDPOINT, sizeof(struct nf_conntrack_man), addrinfo);

    /* set peers configuration */
    peers_nest = peer_nest = NULL;
    lsubnets_nest = lsubnet_nest = psubnets_nest = psubnet_nest = NULL;
    peers_nest = mnl_attr_nest_start(nlh, SVPN_A_PEERS);
    list_for_each_entry(peer, &config->peer_list, node) {
        peer_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, 0); 
        if (!peer_nest)
            goto toobig_peers;
		addrinfo = &peer->addrinfo;
		mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNPEER_A_ENDPOINT, sizeof(struct nf_conntrack_man), addrinfo);

        mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNPEER_A_L4NUM, sizeof(peer->l4num), &peer->l4num);
        mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNPEER_A_FWMARK, sizeof(peer->fwmark), &peer->fwmark);
        mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNPEER_A_ENC, strlen(peer->enc), peer->enc);
        mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNPEER_A_KPP, strlen(peer->kpp), peer->kpp);
        mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNPEER_A_CONNMODE, sizeof(peer->conn_mode), &peer->conn_mode);

        /* local subnets */
		lsubnets_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, SVPNPEER_A_LSUBNET);
		list_for_each_entry(subnet, &peer->local_subnet_list, node) {
			lsubnet_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, 0);
            mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNSUBNET_A_FAMILY, sizeof(__u8), &subnet->family);
            dbg_lprintf("AF_INET is %u, AF_INET6 is %u\n", AF_INET, AF_INET6);
            if (subnet->family == AF_INET)
                mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNSUBNET_A_ADDR, sizeof(subnet->addr.ip), &subnet->addr.ip);
            else if (subnet->family == AF_INET6)
                mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNSUBNET_A_ADDR, sizeof(subnet->addr.ip6), &subnet->addr.ip6);
            mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNSUBNET_A_CIDR, sizeof(__u8), &subnet->cidr);
			mnl_attr_nest_end(nlh, lsubnet_nest);
			lsubnet_nest = NULL;
		}
		mnl_attr_nest_end(nlh, lsubnets_nest);
		lsubnets_nest = NULL;

        /* peer subnets */
		psubnets_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, SVPNPEER_A_PSUBNET);
		list_for_each_entry(subnet, &peer->peer_subnet_list, node) {
			psubnet_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, 0);
            mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNSUBNET_A_FAMILY, sizeof(__u8), &subnet->family);
            if (subnet->family == AF_INET)
                mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNSUBNET_A_ADDR, sizeof(subnet->addr.ip), &subnet->addr.ip);
            else if (subnet->family == AF_INET6)
                mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNSUBNET_A_ADDR, sizeof(subnet->addr.ip6), &subnet->addr.ip6);
            mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, SVPNSUBNET_A_CIDR, sizeof(__u8), &subnet->cidr);
			mnl_attr_nest_end(nlh, psubnet_nest);
			psubnet_nest = NULL;
		}
		mnl_attr_nest_end(nlh, psubnets_nest);
		psubnets_nest = NULL;
		
		mnl_attr_nest_end(nlh, peer_nest);
        peer_nest = NULL;
    }
    mnl_attr_nest_end(nlh, peers_nest);
    peers_nest = NULL;
    goto send;

toobig_peers:
    if (peer_nest)
        mnl_attr_nest_cancel(nlh, peer_nest);
    mnl_attr_nest_end(nlh, peers_nest);
    goto send;
send:
    if (mnlg_socket_send(nlg, nlh) < 0) {
        ret = -errno;
        goto out;
    }
    errno = 0;
    if (mnlg_socket_recv_run(nlg, NULL, NULL) < 0) {
        ret = errno ? -errno : -EINVAL;
        goto out;
    }
out:
    mnlg_socket_close(nlg);
    errno = -ret; /* 恢复之前的errno，防止mnlg_socket_close正确返回将errno清空, 致使上一层看不到出错errno */
    return ret;
}

int ipc_setconf(struct svpn_config *config)
{
    int ret;
    if ((ret = kernel_setconf(config)) < 0)
        return ret;
        
    ret = user_setconf(config);
    return ret;
}
