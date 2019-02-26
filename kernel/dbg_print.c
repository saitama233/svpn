#include <net/tcp.h>
#include "dbg_print.h"

void hexdump(unsigned char *buf, unsigned int len)
{           
    print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,
            16, 1,
            buf, len, false);
}              

void xprint_ip(u8 *prompt, struct nf_conntrack_man *addr, u8 l4num)
{
    printk("%s", prompt);
    if (addr->l3num == AF_INET) {
        printk("IPv4: %pI4, ", &addr->u3.ip); /* nf_conntrack_man.u3.ip是__be32，不需要再转换成大端 */
    } else if (addr->l3num == AF_INET6) {
   		printk("IPv6: %pI6, ", addr->u3.in6.s6_addr);
    } else {
        printk("Cannot parse l3num: %hu\n", addr->l3num);
    }
	if (l4num == IPPROTO_TCP) {
		printk("TCP: %hu\n", ntohs(addr->u.all)); /* nf_conntrack_man.u.all是__be16, 需要转换 */
	} else if (l4num == IPPROTO_UDP) {
		printk("UDP: %hu\n", ntohs(addr->u.all));
	} else {
		printk("Cannot parse l4num: %u\n", l4num);
	}
}

void xprint_sess(struct svpn_session_st *sess)
{
    struct svpn_crypto *crypto = get_crypto(sess);
    struct nf_conntrack_man *src = &sess->tuple.src;
    struct nf_conntrack_man *dst = &sess->tuple.dst;

    xprint_ip("src: ", src, sess->tuple.l4num);
    xprint_ip("dst: ", dst, sess->tuple.l4num);
	xlog("fwmark: %u, seq_no: %u, status: %u\n", 
            sess->fwmark, sess->config.seq_no, sess->status);

	xlog("encstr: %s, kppstr: %s\n", get_encstr(crypto), get_kppstr(crypto));
    xlog("seclen is %u\n", get_seclen(crypto));
	hexdump(get_sec(crypto), get_seclen(crypto));
}

void print_skb_data(struct sk_buff *skb, void *data, int datlen)
{
    pskb_may_pull(skb, datlen);
    printk("Data: ");
    printk("datlen is %d\n", datlen);
    while (datlen--) {
        printk("%c", *(char *)data++);
    }
    printk("\n");
}

void print_skb_l4(struct sk_buff *skb, int l4len)
{
    void *data = NULL;
    int datlen = 0;
    printk("L4: ");
    printk("l4len is %d\n", l4len);
    if (skb->protocol == IPPROTO_TCP) {
        struct tcphdr *l4hdr = tcp_hdr(skb);
        pskb_may_pull(skb, l4hdr->doff << 2);
        printk("TCP 0x%04X, "
               "%hu -> %hu, \n"
               "seq: %u, ack_seq: %u, \n"
               "fin:%d,syn:%d,rst:%d,psh:%d,"
               "ack:%d,urg:%d,ece:%d,cwr:%d\n",
                ntohs(skb->protocol), 
                ntohs(l4hdr->source), ntohs(l4hdr->dest),
                ntohs(l4hdr->seq), ntohs(l4hdr->ack_seq),
                l4hdr->fin, l4hdr->syn, l4hdr->rst, l4hdr->psh,
                l4hdr->ack, l4hdr->urg, l4hdr->ece, l4hdr->cwr);
        data = (void *)l4hdr + (l4hdr->doff << 2);
        skb->data = (unsigned char *)l4hdr + (l4hdr->doff << 2);
        datlen = l4len - (l4hdr->doff << 2);
    } else if (skb->protocol == IPPROTO_UDP) {
        struct udphdr *l4hdr = udp_hdr(skb);
        pskb_may_pull(skb, sizeof(struct udphdr));
        printk("UDP 0x%04X, %hu -> %hu \n",
                ntohs(skb->protocol), ntohs(l4hdr->source), ntohs(l4hdr->dest));
        data = (void *)l4hdr + sizeof(struct udphdr);
        /* 需要设置skb->data，否则之后无法从pskb_may_pull得到正确的结果， */
        skb->data = (unsigned char *)l4hdr + sizeof(*l4hdr);
        datlen = l4len - sizeof(struct udphdr);
    } else if (skb->protocol == IPPROTO_ICMP) {
        printk("ICMP 0x%04X, \n",
                ntohs(skb->protocol));
        /* fixme: 暂时没对ICMP进行处理，因为不同类型的ICMP长度不一样，不好处理 */
        return;
    }
    print_skb_data(skb, data, datlen);
}

void print_skb_l3(struct sk_buff *skb)
{
    int l4len = 0;
    printk("L3: ");
    if (skb->protocol == __constant_htons(ETH_P_IP)) {
        struct iphdr *l3hdr = ip_hdr(skb);
        pskb_may_pull(skb, l3hdr->ihl << 2);
        /* printk("IPv4 0x%04X, " NIPQUAD_FMT " -> " NIPQUAD_FMT " \n", */
                /* ntohs(skb->protocol), NIPQUAD(l3hdr->saddr), NIPQUAD(l3hdr->daddr)); */
        printk("IPv4: 0x%04X, %pI4 -> %pI4, " 
                "ihl: %d, version: %d, "
                "tot_len: %d, id: 0x%04X, protocol: %hu\n",
                ntohs(skb->protocol), &l3hdr->saddr, &l3hdr->daddr, 
                l3hdr->ihl, l3hdr->version, 
                ntohs(l3hdr->tot_len), ntohs(l3hdr->id), l3hdr->protocol);
        skb->protocol = l3hdr->protocol;
        skb_set_transport_header(skb, l3hdr->ihl << 2);
        l4len = ntohs(l3hdr->tot_len) - (l3hdr->ihl << 2);
    } else if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
        /* fixme:未进行测试，而且没有处理扩展头部 */
        struct ipv6hdr *l3hdr = ipv6_hdr(skb);
        printk("IPv6 0x%04X, %pI6 -> %pI6 \n",
               ntohs(skb->protocol), l3hdr->saddr.s6_addr, l3hdr->daddr.s6_addr); // 这里的地址输出可能有误，没有进行测试，
        skb->protocol = l3hdr->nexthdr;
        skb_set_transport_header(skb, sizeof(*l3hdr));
        l4len = htons(l3hdr->payload_len); // 这里计算不准确，因为还有扩展头部
    }
    skb->data = skb_transport_header(skb);
    print_skb_l4(skb, l4len);
}

void print_skb_l2(struct sk_buff *skb)
{
    printk("L2: ");
    /* LOCAL_OUT和PRE_ROUTING处没有链路层头，mac_header为65535 */
    /* printk("skb->mac_header is %d\n", skb->mac_header); */
    if (skb_mac_header_was_set(skb)) {
        struct ethhdr *l2hdr = eth_hdr(skb);
        printk("Ethernet %pM -> %pM, h_proto: 0x%04X",
                l2hdr->h_source, l2hdr->h_dest, ntohs(l2hdr->h_proto));
        /* printk("SOURCE:" MAC_FMT "\n", MAC_ARG(l2hdr->h_source)); */
        /* printk("DEST:" MAC_FMT "\n", MAC_ARG(l2hdr->h_dest)); */
        skb->protocol = l2hdr->h_proto;
        skb_set_network_header(skb, sizeof(*l2hdr));
    }
    printk("\n");
    /* 准备进入第三层，将skb->data指向第三层的起始位置 */
    skb->data = skb_network_header(skb);
    print_skb_l3(skb);
}

void print_skb(struct sk_buff *skb)
{
#if DEBUG
    struct sk_buff *nskb;
    nskb = skb_copy(skb, GFP_ATOMIC);
    if (!nskb) {
        xlog("skb_copy error\n");
        goto out;
    }
    printk("dev is %s\n", nskb->dev->name);
    printk("mark is %d\n", nskb->mark);
    /* 使用skb_set_network_header前，需要将skb->data移动到正确的位置，
     * 将要进入第二层，skb->data需要指向第二层起始位置 */
    nskb->data = skb_mac_header(nskb);
    print_skb_l2(nskb);

out:
    if (nskb)
        kfree_skb(nskb);
#endif
}

