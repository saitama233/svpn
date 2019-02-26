#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include "svpn_kernel.h"
#include "netlink.h"
#include "hooks.h"

struct svpn_st *gl_svpn;

struct svpn_st *get_gl_svpn(void)
{
    if (unlikely(!gl_svpn)) {
        xlog("svpn null\n");
        /* fixme: 应该删除模块 */
    }
    return gl_svpn;
}

/*
netdev_tx_t svpndev_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct iphdr *iph = ip_hdr(skb);
    char *ipstr = "127.0.0.1";
    __be32 ip = 0;
    printk("in svpndev_start_xmit, dev: %s\n", dev->name);

    in4_pton(ipstr, strlen(ipstr), (u8 *)&ip, -1, NULL);
    xlog("in4_pton from 127.0.0.1 to %u\n", ip);
    iph->saddr = ip;
    iph->daddr = ip;
}
*/

static int __init svpn_init(void)
{
    int ret = -ENOMEM;
    xlog("svpn_init begin\n");

	gl_svpn = kzalloc(sizeof(struct svpn_st), GFP_ATOMIC);
	if (!gl_svpn) {
		xlog("kzalloc gl_svpn error\n");
		return ret;
	}

    gl_svpn->sess_arr = kzalloc(sizeof(struct svpn_session_st *) * 1024, GFP_ATOMIC);
    if (!gl_svpn->sess_arr) {
        xlog("kzalloc gl_svpn->sess_arr error\n");
        return ret;
    }

	spin_lock_init(&gl_svpn->inst_lock);
	spin_lock_init(&gl_svpn->sess_lock);

	gl_svpn->inst_ht_size = 0x0400; /* instance hash table size 1024 */	
	gl_svpn->sess_ht_size = 0x0400; /* session hash table size 1024 */	

    INIT_LIST_HEAD(&gl_svpn->inst_list);

	gl_svpn->inst_htable = kzalloc(sizeof(struct svpn_instance_st) * gl_svpn->inst_ht_size, GFP_ATOMIC); /* hash长度 1024 */
	if (!gl_svpn->inst_htable) {
		xlog("kzalloc gl_svpn->inst_htable error\n");
		goto err;
	}
	/* 因为用的是kzalloc, 可以不对每个元素进行初始化 */
	for (int i = 0; i < gl_svpn->inst_ht_size; i++) {
    	INIT_HLIST_HEAD(&gl_svpn->inst_htable[i]);
	}

	gl_svpn->sess_htable = kzalloc(sizeof(struct svpn_session_st) * gl_svpn->sess_ht_size, GFP_ATOMIC); /* hash长度 1024 */
	if (!gl_svpn->sess_htable) {
		xlog("kzalloc gl_svpn->sess_htable error\n");
		goto err;
	}
	for (int i = 0; i < gl_svpn->sess_ht_size; i++) {
    	INIT_HLIST_HEAD(&gl_svpn->sess_htable[i]);
	}

	gl_svpn->inst_kmc = kmem_cache_create("svpn_instance", sizeof(struct svpn_instance_st), 0,0, NULL);
	if (!gl_svpn->inst_kmc) {
		xlog("kmem_cache_create gl_svpn->inst_kmc error\n");
		goto err;
	}

	gl_svpn->sess_kmc = kmem_cache_create("svpn_session", sizeof(struct svpn_session_st), 0,0, NULL);
	if (!gl_svpn->sess_kmc) {
		xlog("kmem_cache_create gl_svpn->sess_kmc error\n");
		goto err;
	}

    ret = svpn_hooks_init();
    if (ret < 0) {
        xlog("Can't register svpn_ops hook!\n");
        goto err;
    }
    if ((ret = svpn_genetlink_init()) < 0) {
        xlog("svpn_genetlink_init error\n");
        goto err;
    }
	return 0;
err:
	if (gl_svpn->inst_kmc)
		kmem_cache_destroy(gl_svpn->inst_kmc);
	if (gl_svpn->sess_kmc)
		kmem_cache_destroy(gl_svpn->sess_kmc);
	if (gl_svpn->inst_htable)
		kfree(gl_svpn->inst_htable);
	if (gl_svpn->sess_htable)
		kfree(gl_svpn->sess_htable);
    if (gl_svpn->sess_arr)
        kfree(gl_svpn->sess_arr);
	if (gl_svpn)
		kfree(gl_svpn);	
    return ret;
}

static void svpn_cleanup(void)
{
    struct svpn_st *svpn = get_gl_svpn();
    struct svpn_instance_st *inst;

    svpn_hooks_uninit();
    svpn_genetlink_uninit();

    /* 分别测试了while (!list_empty) 和 list_for_each_entry_safe来遍历删除 */
    while (!list_empty(&svpn->inst_list)) {
        xlog("in while (!list_empty(&svpn->inst_list)) \n");
        inst = list_first_entry(&svpn->inst_list, struct svpn_instance_st, list_node);
        list_del_init(&inst->list_node);
        
        struct svpn_session_st *sess, *sess_next;
        list_for_each_entry_safe(sess, sess_next, &inst->sess_list, list_node) {
            xlog("list_for_each_entry_safe \n");
            list_del_init(&sess->list_node);
            kmem_cache_free(svpn->sess_kmc, sess);
        }
        unregister_netdev(inst->dev);
        free_netdev(inst->dev);
        kmem_cache_free(svpn->inst_kmc, inst);
    }

    xlog("before kmem_cache_destroy(svpn->inst_kmc); \n");
    if (svpn->inst_kmc)
        kmem_cache_destroy(svpn->inst_kmc);
    xlog("after kmem_cache_destroy(svpn->inst_kmc); \n");
    if (svpn->sess_kmc)
        kmem_cache_destroy(svpn->sess_kmc);
    if (svpn->inst_htable)
        kfree(svpn->inst_htable);
    if (svpn->sess_htable)
        kfree(svpn->sess_htable);
    if (gl_svpn->sess_arr)
        kfree(gl_svpn->sess_arr);
	if (svpn)
		kfree(svpn);
    /* fixme: 将gl_svpn清零 */
}

static void __exit svpn_exit(void)
{
    xlog("svpn_exit begin\n");
    svpn_cleanup();
    xlog("svpn_exit end\n");
}

module_init(svpn_init);
module_exit(svpn_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jesse");
MODULE_DESCRIPTION("simple vpn");
