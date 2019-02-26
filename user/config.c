#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h> /* ETH_P_IP */
#include <netdb.h>
#include <ctype.h>
#include "config.h"

#define COMMENT_CHAR '#'

static char *get_value(char *line, const char *key)
{
    size_t linelen = strlen(line);
    size_t keylen = strlen(key);

    if (keylen >= linelen)
        return NULL;

    if (strncasecmp(line, key, keylen))
        return NULL;

    return line + keylen;
}

/* value is fmt like "IP:port" */
static inline bool parse_endpoint(struct nf_conntrack_man *endpoint, const char *value)
{
	struct addrinfo *result;
    struct addrinfo hints = {
    	.ai_family = AF_UNSPEC,
    	.ai_socktype = SOCK_DGRAM,
    	.ai_protocol = IPPROTO_UDP
	};
    char *node, *service;
	int ret;
    char *mutable = strdup(value);

    if (!mutable) {
        lprintf("strdup error\n");
        return false;
    }

    if (!strlen(value)) {
        free(mutable);
        lprintf("Unable to parse empty endpoint\n");
        return false;
    }

    node = mutable;
    service = strchr(mutable, ':');
    if (!service) {
        free(mutable);
        lprintf("Unable to find the port!\n");
        return false;
    }
    *service++ = '\0';

	/* 带重试的getaddrinfo */
    for (unsigned int timeout = 1000000;;) {
        ret = getaddrinfo(node, service, &hints, &result);
        if (!ret)
            break;
        timeout = timeout * 3 / 2;
        /* The set of return codes that are "permanent failures". All other possibilities are potentially transient.
         *
         * This is according to https://sourceware.org/glibc/wiki/NameResolver which states:
         *  "From the perspective of the application that calls getaddrinfo() it perhaps
         *   doesn't matter that much since EAI_FAIL, EAI_NONAME and EAI_NODATA are all
         *   permanent failure codes and the causes are all permanent failures in the
         *   sense that there is no point in retrying later."
         *
         * So this is what we do, except FreeBSD removed EAI_NODATA some time ago, so that's conditional.
         */
        if (ret == EAI_NONAME || ret == EAI_FAIL ||
            #ifdef EAI_NODATA
                ret == EAI_NODATA ||
            #endif
                timeout >= 90000000) {
            free(mutable);
            lprintf("%s: '%s'\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value);
            return false;
        }
        lprintf("%s: '%s'. Trying again in %.2f seconds...\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value, timeout / 1000000.0);
        usleep(timeout);
    }

	if (result->ai_family == AF_INET && result->ai_addrlen == sizeof(struct sockaddr_in)) {
		endpoint->u3.ip = ((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr;
		endpoint->u.all = ((struct sockaddr_in *)(result->ai_addr))->sin_port;
        endpoint->l3num = AF_INET; /* 小端存储 */
        dbg_lprintf("ETH_P_IP is %hu\n", ETH_P_IP);
        dbg_lprintf("endpoint->u3.ip is " NIPQUAD_FMT "\n", NIPQUAD(endpoint->u3.ip));
        dbg_lprintf("endpoint->u.all is %" PRIu16 "\n", ntohs(endpoint->u.all));
	} else if (result->ai_family == AF_INET6 && result->ai_addrlen == sizeof(struct sockaddr_in6)) {
		memcpy(endpoint->u3.ip6, ((struct sockaddr_in6 *)(result->ai_addr))->sin6_addr.s6_addr, sizeof(struct in6_addr));
		endpoint->u.all = ((struct sockaddr_in6 *)(result->ai_addr))->sin6_port;
        endpoint->l3num = AF_INET6;
        dbg_lprintf("ETH_P_IPV6 is %hu\n", ETH_P_IPV6);
        dbg_lprintf("endpoint->u3.ip6 is " NIP6_FMT "\n", NIP6(endpoint->u3.in6.s6_addr));
        dbg_lprintf("endpoint->u.all is %" PRIu16 "\n", ntohs(endpoint->u.all));
	} else {
	    freeaddrinfo(result);
        free(mutable);
	    lprintf("Neither IPv4 nor IPv6 address found: '%s'\n", value);
	    return false;
	}
	freeaddrinfo(result);
    free(mutable);

	return true;
}

static inline bool parse_ip(struct svpn_subnet *subnet, const char *ipstr)
{   
    subnet->family = AF_UNSPEC;
    if (strchr(ipstr, ':')) {
        if (inet_pton(AF_INET6, ipstr, &subnet->addr.in) == 1)
            subnet->family = AF_INET6;
    } else {
        if (inet_pton(AF_INET, ipstr, &subnet->addr.in6) == 1)
            subnet->family = AF_INET;
    }   
    if (subnet->family == AF_UNSPEC) {
        lprintf("Unable to parse IP address: `%s'\n", ipstr);
        return false;
    }       
    return true;
}

/* fmt like 192.168.0.0/24,192.168.1.0/18,3ffe:ffff:0:f101::1/64 */
static bool parse_subnet(struct list_head *subnet_list, char *value)
{
	struct svpn_subnet *new_subnet = NULL;
    char *mutable = strdup(value), *sep, *saved_entry;
	char *ip, *mask;

    if (!mutable) {
        lprintf("strdup error\n");
        return false;
    }

    if (!strlen(value)) {
        free(mutable);
        /* fixme: 返回值可能有误 */
        return true;
    }

	sep = mutable;
	while ((mask = strsep(&sep, ","))) { /* sep每次指向分隔符','后的字符，mask指向sep原来的位置 */
		unsigned long cidr;
		char *end;

		saved_entry = strdup(mask);
		ip = strsep(&mask, "/");
		new_subnet = calloc(1, sizeof(struct svpn_subnet));
        if (!new_subnet) {
            lprintf("calloc error\n");
			free(saved_entry);
            free(mutable);
            return false;
        }
        if (!parse_ip(new_subnet, ip)) {
            free(new_subnet);
			free(saved_entry);
            free(mutable);
            return false;
        }
	    snprintf(new_subnet->ipstr, sizeof(new_subnet->ipstr), "%s", saved_entry);
        if (mask) {
            if (!isdigit(mask[0]))
                goto err;
            cidr = strtoul(mask, &end, 10);
            if (*end || (cidr > 32 && new_subnet->family == AF_INET) || (cidr > 128 && new_subnet->family == AF_INET6))
                goto err;
        } else if (new_subnet->family == AF_INET)
            cidr = 32;
        else if (new_subnet->family == AF_INET6)
            cidr = 128;
        else
            goto err;
        new_subnet->cidr = cidr;
		list_add(&new_subnet->node, subnet_list);
		free(saved_entry);
        if (new_subnet->family == AF_INET) {
            dbg_lprintf("new_subnet, ipstr: %s, family: AF_INET, ip is " NIPQUAD_FMT ", cidr: %d\n", 
                    new_subnet->ipstr, NIPQUAD(new_subnet->addr.in.s_addr), new_subnet->cidr);
        } else if (new_subnet->family == AF_INET6) {
            dbg_lprintf("new_subnet, ipstr: %s, family: AF_INET6, ip6 is " NIP6_FMT ", cidr: %d\n", 
                    new_subnet->ipstr, NIP6(new_subnet->addr.in6.s6_addr), new_subnet->cidr);
        }
	}

	free(mutable);
    return true;
err:
    free(new_subnet);
    free(mutable);
    fprintf(stderr, "AllowedIP is not in the correct format: `%s'\n", saved_entry);
    free(saved_entry);
    return false;
}

static bool parse_l4num(__u8 *l4num, char *value)
{
    if (strcaseeq(value, "TCP"))
        *l4num = IPPROTO_TCP;
    else if (strcaseeq(value, "UDP"))
        *l4num = IPPROTO_UDP;
    else {
        lprintf("Cannot parse l4num: %s\n", value);
        return false;
    }

    return true;
}

static bool parse_enc(char *enc, char *value)
{
    if (strcaseeq(value, "AES-128-GCM")) {
        snprintf(enc, CRYPTO_MAX_ALG_NAME, "gcm(aes)");
    } else {
        lprintf("Cannot parse encryption: %s\n", value);
        return false;
    }
    return true;
}

static bool parse_kpp(char *kpp, char *value)
{
    if (strcaseeq(value, "ECDH")) {
        snprintf(kpp, KPP_METHOD_LEN, "ecdh");
    } else {
        lprintf("Cannot parse Key-agreement Protocol Primitives: %s\n", value);
        return false;
    }
    return true;
}

static bool parse_fwmark(__u32 *fwmark, char *value)
{
	char *end;
	int base = 10;
	int ret;

    if (strlen(value) > 2 && value[0] == '0' && value[1] == 'x')
        base = 16;

    ret = strtoul(value, &end, base);
	if (*end || ret > UINT32_MAX)
        goto err;

    *fwmark = ret;
	return true;

err:
	lprintf("Cannot parse fwmark: %s\n", value);
	return false;
}

static bool parse_connmode(__u8 *conn_mode, char *value)
{
    if (strcaseeq(value, "active")) {
        *conn_mode = CONNECTION_ACTIVE;
    } else if (strcaseeq(value, "passive")) {
        *conn_mode = CONNECTION_PASSIVE;
    } else {
        lprintf("Cannot parse the connection mode: %s\n", value);
        return false;
    }
    return true;
}

static bool process_line(struct config_ctx *ctx, char *line)
{
    char *value;
    bool ret = true;

	if (!strcasecmp(line, "[local]")) {
        dbg_lprintf("in local area\n");
    	ctx->is_peer_section = false;
    	ctx->is_local_section = true;
    	return true;
	} else if (!strcasecmp(line, "[peer]")) {
        dbg_lprintf("in peer area\n");
        struct svpn_peer *new_peer = calloc(1, sizeof(struct svpn_peer));

        if (!new_peer) {
            lprintf("calloc error new_peer\n");
            return false;
        }
        INIT_LIST_HEAD(&new_peer->local_subnet_list);
        INIT_LIST_HEAD(&new_peer->peer_subnet_list);

		list_add(&new_peer->node, &ctx->config->peer_list);
        ctx->is_peer_section = true;
        ctx->is_local_section = false;
		return true;
	}

/* 每次调用key_match，value都会指向当前key的值 */
#define key_match(key) (value = get_value(line, key "="))

    if (ctx->is_local_section) {
        if (key_match("LocalPoint"))
    		ret = parse_endpoint(&ctx->config->local.addrinfo, value);
    } else if (ctx->is_peer_section) {
		struct svpn_peer *tmp_peer = list_entry(ctx->config->peer_list.next, struct svpn_peer, node);
        if (key_match("PeerPoint")) {
            ret = parse_endpoint(&tmp_peer->addrinfo, value);
		} else if (key_match("LocalSubnets")) {
            dbg_lprintf("in LocalSubnets\n");
			ret = parse_subnet(&tmp_peer->local_subnet_list, value);
		} else if (key_match("PeerSubnets")) {
            dbg_lprintf("in PeerSubnets\n");
			ret = parse_subnet(&tmp_peer->peer_subnet_list, value);
		} else if (key_match("TransportProtocol")) {
            ret = parse_l4num(&tmp_peer->l4num, value);
            if (tmp_peer->l4num == IPPROTO_TCP) {
                dbg_lprintf("l4num is IPPROTO_TCP\n");
            } else if (tmp_peer->l4num == IPPROTO_UDP) {
                dbg_lprintf("l4num is IPPROTO_UDP\n");
            }
        } else if (key_match("ENC")) {
            ret = parse_enc(tmp_peer->enc, value);
            dbg_lprintf("enc is %s\n", tmp_peer->enc);
        } else if (key_match("KPP")) {
            ret = parse_kpp(tmp_peer->kpp, value);
            dbg_lprintf("kpp is %s\n", tmp_peer->kpp);
        } else if (key_match("mark")) {
            ret = parse_fwmark(&tmp_peer->fwmark, value);
            dbg_lprintf("mark is %d\n", tmp_peer->fwmark);
        } else if (key_match("ConnMode")) {
            ret = parse_connmode(&tmp_peer->conn_mode, value);
        }
    }
    return ret;
}

bool config_read_init(struct config_ctx *ctx, bool append)
{
    memset(ctx, 0, sizeof(struct config_ctx));
    ctx->config = calloc(1, sizeof(struct svpn_config));
    if (!ctx->config) {
        lprintf("calloc ctx->config error\n");
        return false;
    }
	INIT_LIST_HEAD(&ctx->config->peer_list);

    return true;
}

bool config_read_line(struct config_ctx *ctx, const char *input)
{
    size_t len, cleaned_len = 0;
    char *line = NULL, *comment;
    bool ret = true;

    /* This is what strchrnul is for, but that isn't portable. */
    /* 处理注释 */
    comment = strchr(input, COMMENT_CHAR);
    if (comment)
        len = comment - input;
    else
        len = strlen(input);

    if (!len)
        goto out;

    line = calloc(len + 1, sizeof(char));
    if (!line) {
        lprintf("calloc error");
        ret = false;
        goto out;
    }

    /* 去除空格 */
	for (size_t i = 0; i < len; ++i) {
        if (!isspace(input[i]))
            line[cleaned_len++] = input[i];
    }
    ret = process_line(ctx, line);
out:
    if (line)
        free(line);
    if (!ret)
        free(ctx->config);
    return ret;
}

struct svpn_config *config_read_finish(struct config_ctx *ctx)
{
    return ctx->config;
}
