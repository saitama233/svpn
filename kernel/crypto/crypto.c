#include <crypto/aead.h>
#include "crypto.h"

#define GCM_AES_IV_LEN 12
#define GCM_AES_AD_LEN 8

struct alg_desc {
    const char *alg;
    int (*init)(struct svpn_session_st *sess);
    int (*encrypt)(struct sk_buff *skb, struct svpn_session_st *sess);
    int (*decrypt)(struct sk_buff *skb, struct svpn_session_st *sess);
};

static int alg_aead_init(struct svpn_session_st *sess)
{
	struct svpn_crypto *crypto = get_crypto(sess);
    struct crypto_aead **aead = &crypto->aead; // get_aead(crypto);
    int ret = 0;
    xlog("in alg_aead_init\n");

    xlog("crypto->encstr is %s\n", crypto->encstr);
    *aead = crypto_alloc_aead(get_encstr(crypto), 0, 0);
    if (IS_ERR(*aead)) {
		xlog("crypto_alloc_aead error\n");
		ret = PTR_ERR(*aead);
		*aead = NULL;
        return ret;
	}
    xlog("crypto_alloc_aead ok\n");
    int ivlen = crypto_aead_ivsize(*aead);
    xlog("ivlen is %d\n", ivlen);

    ret = crypto_aead_setkey(*aead, get_sec(crypto), get_seclen(crypto));
    if (ret < 0) {
		xlog("crypto_aead_setkey error\n");
        goto fail;
	}
    xlog("crypto_aead_setkey ok\n");
    int blksize = ALIGN(crypto_aead_blocksize(*aead), 4);
    xlog("blksize is %d\n", blksize);

	if (!get_authsize(crypto)) {
		set_authsize(crypto, DEFAULT_AUTHSIZE);
	}
    xlog("get_authsize(crypto) is %d\n", get_authsize(crypto));
    ret = crypto_aead_setauthsize(*aead, get_authsize(crypto));
    if (ret < 0) {
		xlog("crypto_aead_setauthsize error\n");
        goto fail;
	}
    xlog("crypto_aead_setauthsize ok\n");

    return ret;
fail:
    crypto_free_aead(*aead);
	*aead = 0;
    return ret;
}

static struct aead_request *alloc_aead_req(struct crypto_aead *aead,
                         unsigned char **iv,
						 unsigned char **ad,
                         struct scatterlist **sg,
                         int num_frags)
{
	size_t size, iv_offset, ad_offset, sg_offset;
	struct aead_request *req;
	void *tmp;
	
	size = sizeof(struct aead_request) + crypto_aead_reqsize(aead);
	iv_offset = size;
    size += GCM_AES_IV_LEN;

	ad_offset = size;
	size += GCM_AES_AD_LEN;
    xlog("size if %zd\n", size);

    xlog("__alignof__(struct scatterlist) is %lu\n", __alignof__(struct scatterlist));
	size = ALIGN(size, __alignof__(struct scatterlist));
    xlog("size if %zd\n", size);
	sg_offset = size;
	size += sizeof(struct scatterlist) * num_frags;
    xlog("sizeof(struct aead_request) + crypto_aead_reqsize(aead) is %zd\n",
            sizeof(struct aead_request) + crypto_aead_reqsize(aead));
    xlog("sizeof(struct scatterlist) is %zd, num_frags is %d\n",
            sizeof(struct scatterlist), num_frags);
    xlog("size is %zd, iv_offset is %zd, ad_offset is %zd, sg_offset is %zd\n",
            size, iv_offset, ad_offset, sg_offset);

	tmp = kzalloc(size, GFP_ATOMIC);
	if (!tmp) {
		xlog("kzalloc tmp err\n");
        return NULL;
	}

	*iv = (unsigned char *)(tmp + iv_offset);
	*ad = (unsigned char *)(tmp + ad_offset);
    *sg = (struct scatterlist *)(tmp + sg_offset);
    req = tmp;
    xlog("req is %p, *iv is %p, *ad is %p, *sg is %p\n", req, *iv, *ad, *sg);

	aead_request_set_tfm(req, aead);

	return req;
}

/* fixme: iv和ad的填充需要改变 */
static void svpn_fill_iv(unsigned char *iv, struct svpn_session_st *sess)
{
	struct svpn_config *config = get_config(sess);
    __u32 seq_no = get_seq_no(config) + 1;
    xlog("in svpn_fill_iv\n");
	memcpy(iv, &seq_no, sizeof(__be32));
	memcpy(&iv[4], &seq_no, sizeof(__be32));
	memcpy(&iv[8], &seq_no, sizeof(__be32));
}

static void svpn_fill_ad(unsigned char *ad, struct svpn_session_st *sess)
{
	struct svpn_config *config = get_config(sess);
    __u32 seq_no = get_seq_no(config) + 2;
    xlog("in svpn_fill_ad\n");
	memcpy(ad, &seq_no, sizeof(__be32));
	memcpy(&ad[4], &seq_no, sizeof(__be32));
}

static int alg_aead_encrypt(struct sk_buff *skb, struct svpn_session_st *sess)
{
	struct svpn_crypto *crypto = get_crypto(sess);
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sgin;
	unsigned char *iv, *ad;
    int alen = crypto_aead_authsize(get_aead(crypto));
    xlog("alen is %d\n", alen);
	int ret, nsg;
    unsigned int len;
    xlog("in alg_aead_encrypt\n");

	ret = skb_cow_data(skb, 0, &trailer);
	if (unlikely(ret < 0)) {
		xlog("skb_cow_data error\n");
		return -1;
	}
    xlog("skb_cow_data ok\n");
	nsg = ret + 1;
    xlog("nsg is %d\n", nsg);
	req = alloc_aead_req(get_aead(crypto), &iv, &ad, &sgin, nsg);
	if (!req) {
		xlog("alloc_aead_req error\n");
		return -1;
	}
    xlog("req is %p, iv is %p, ad is %p, sg is %p\n", req, iv, ad, sgin);
    xlog("alloc_aead_req ok\n");
	svpn_fill_iv(iv, sess);
    xlog("iv is \n");
    hexdump(iv, GCM_AES_IV_LEN);
	svpn_fill_ad(ad, sess);
    xlog("ad is \n");
    hexdump(ad, GCM_AES_AD_LEN);

	sg_init_table(sgin, nsg);
	sg_set_buf(&sgin[0], ad, GCM_AES_AD_LEN);
    xlog("sg_set_buf sgin[0] ok\n");

    xlog("before skb_put skb->len is %u\n", skb->len);
    /* 需要给authtag分配空间，放在需要加密的空间后，aead_request_set_crypt介绍里有提到  */
    /* fixme: 不确定是否需要使用skb_put，尾部的空间也可能不够，这样skb_put会导致panic */
    skb_put(skb, alen);
    xlog("after akb_put skb->len is %u\n", skb->len);
	nsg = skb_to_sgvec(skb, &sgin[1], 0, skb->len);
	if (nsg < 0) {
    	ret = nsg;
    	goto out;
	}
    xlog("skb_to_sgvec ok\n");

	len = skb->len - alen;
	aead_request_set_crypt(req, sgin, sgin, len, iv);
	aead_request_set_ad(req, GCM_AES_AD_LEN);
    xlog("aead_request_set_ad ok\n");

	ret = crypto_aead_encrypt(req);
    xlog("crypto_aead_encrypt ok\n");
    if (ret == -EINPROGRESS) {
        return ret;
    } else if (ret != 0) {
        aead_request_free(req);
        return -EINVAL;
    }

out:
	aead_request_free(req);
	return ret;
}

static int alg_aead_decrypt(struct sk_buff *skb, struct svpn_session_st *sess)
{
	struct svpn_crypto *crypto = get_crypto(sess);
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sgin;
	unsigned char *iv, *ad;
    int alen = crypto_aead_authsize(get_aead(crypto));
    xlog("alen is %d\n", alen);
	int ret, nsg;
    unsigned int len;

	ret = skb_cow_data(skb, 0, &trailer);
	if (unlikely(ret < 0)) {
		xlog("skb_cow_data error\n");
		return -1;
	}
	nsg = ret + 1;
	req = alloc_aead_req(get_aead(crypto), &iv, &ad, &sgin, nsg);
	if (!req) {
		xlog("alloc_aead_req error\n");
		return -1;
	}
	svpn_fill_iv(iv, sess);
	svpn_fill_ad(ad, sess);

	sg_init_table(sgin, nsg);
	sg_set_buf(&sgin[0], ad, GCM_AES_AD_LEN);

	nsg = skb_to_sgvec(skb, &sgin[1], 0, skb->len);
	if (nsg < 0) {
    	ret = nsg;
    	goto out;
	}

	len = skb->len;
	aead_request_set_crypt(req, sgin, sgin, len, iv);
	aead_request_set_ad(req, GCM_AES_AD_LEN);

    xlog("before crypto_aead_decrypt: skb->len is %u\n", skb->len);
	ret = crypto_aead_decrypt(req);
    /* 这里的错误处理有问题 */
    if (ret == -EINPROGRESS) {
        return ret;
    } else if (ret != 0) {
        aead_request_free(req);
        return -EINVAL;
    }
    xlog("after crypto_aead_decrypt: skb->len is %u\n", skb->len);
    /* FIXME: 将尾部的alen去除,(对应于加密的skb_put) crypto_aead_decrypt不会缩减skb的长度 */
    skb_trim(skb, skb->len - alen);
    xlog("after skb_trim: skb->len is %u\n", skb->len);

out:
	aead_request_free(req);
	return ret;
}

/* 数组的alg字段需要按字母顺序排序，因为alg_find使用的是二分查找 */
static const struct alg_desc alg_descs[] = {
	{
	    .alg = "gcm(aes)",
		.init = alg_aead_init,
		.encrypt = alg_aead_encrypt,
		.decrypt = alg_aead_decrypt,
	},
};

/* 二分查找 */
int alg_find(const char *alg)
{
    int start = 0;
    int end = ARRAY_SIZE(alg_descs);

    while (start < end) {
        int i = (start + end) / 2;
        int diff = strcmp(alg_descs[i].alg, alg);

        if (diff > 0) {
            end = i;
            continue;
        }

        if (diff < 0) {
            start = i + 1;
            continue;
        }

        return i;
    }

    return -1;
}

int sess_crypto_init(struct svpn_session_st *sess)
{
    struct svpn_crypto *crypto = get_crypto(sess);

    set_encid(crypto, alg_find(get_encstr(crypto)));
    if (get_encid(crypto) < 0) {
        xlog("alg_find error, cannot find %s\n", get_encstr(crypto));
		return -1;
    }

	if (alg_descs[get_encid(crypto)].init(sess) < 0) {
		xlog("init error\n");
		return -1;
	}

    return 0;
}

int sess_encrypt(struct sk_buff *skb, struct svpn_session_st *sess)
{
    struct svpn_crypto *crypto = get_crypto(sess);
	return alg_descs[get_encid(crypto)].encrypt(skb, sess);
}

int sess_decrypt(struct sk_buff *skb, struct svpn_session_st *sess)
{
    struct svpn_crypto *crypto = get_crypto(sess);
	return alg_descs[get_encid(crypto)].decrypt(skb, sess);
}

