/* SPDX-License-Identifier: GPL-2.0 */

#include <stdlib.h>
#include <errno.h> /* ENOMEM */
#include <time.h>
#include "mnlg.h"

struct mnlg_socket {
    struct mnl_socket *nl;
    char *buf;
    uint16_t id; /* 存储family_name的id */
    uint8_t version;
    unsigned int seq;
    unsigned int portid;
};

/* 准备netlink header和general netlink header */
static struct nlmsghdr *__mnlg_msg_prepare(struct mnlg_socket *nlg, uint8_t cmd,
                       uint16_t flags, uint16_t id,
                       uint8_t version)
{                      
    struct nlmsghdr *nlh;
    struct genlmsghdr *genl;
   
	/* 准备netlink header */
    nlh = mnl_nlmsg_put_header(nlg->buf);
    nlh->nlmsg_type = id;
    nlh->nlmsg_flags = flags;
    nlg->seq = time(NULL); 
    nlh->nlmsg_seq = nlg->seq;
    
	/* 准备general netlink header */
    genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    genl->cmd = cmd;
    genl->version = version;
    
    return nlh;
}

struct nlmsghdr *mnlg_msg_prepare(struct mnlg_socket *nlg, uint8_t cmd,
                  uint16_t flags)
{   
    return __mnlg_msg_prepare(nlg, cmd, flags, nlg->id, nlg->version);
}

int mnlg_socket_send(struct mnlg_socket *nlg, const struct nlmsghdr *nlh)
{
    return mnl_socket_sendto(nlg->nl, nlh, nlh->nlmsg_len);
}

static int mnlg_cb_noop(const struct nlmsghdr *nlh, void *data)
{
    (void)nlh;
    (void)data;
    return MNL_CB_OK;
}

static int mnlg_cb_error(const struct nlmsghdr *nlh, void *data)
{
    const struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
    (void)data;

    if (nlh->nlmsg_len < mnl_nlmsg_size(sizeof(struct nlmsgerr))) {
        errno = EBADMSG;
        return MNL_CB_ERROR;
    }
    /* Netlink subsystems returns the errno value with different signess */
    if (err->error < 0)
        errno = -err->error;
    else
        errno = err->error;

    return err->error == 0 ? MNL_CB_STOP : MNL_CB_ERROR;
}

static int mnlg_cb_stop(const struct nlmsghdr *nlh, void *data)
{
    (void)data;
    if (nlh->nlmsg_flags & NLM_F_MULTI && nlh->nlmsg_len == mnl_nlmsg_size(sizeof(int))) {
        int error = *(int *)mnl_nlmsg_get_payload(nlh);
        /* Netlink subsystems returns the errno value with different signess */
        if (error < 0)
            errno = -error;
        else
            errno = error;

        return error == 0 ? MNL_CB_STOP : MNL_CB_ERROR;
    }
    return MNL_CB_STOP;
}

/* mnlg_socket_recv_run中mnl_cb_run2根据回调的返回值调用 */
static mnl_cb_t mnlg_cb_array[] = {
    [NLMSG_NOOP]    = mnlg_cb_noop,
    [NLMSG_ERROR]   = mnlg_cb_error,
    [NLMSG_DONE]    = mnlg_cb_stop,
    [NLMSG_OVERRUN] = mnlg_cb_noop,
};

int mnlg_socket_recv_run(struct mnlg_socket *nlg, mnl_cb_t data_cb, void *data)
{   
    int err;
    
    do {
        err = mnl_socket_recvfrom(nlg->nl, nlg->buf,
                      MNL_SOCKET_BUFFER_SIZE);
        if (err <= 0)
            break;
		/* 当一次接收了多个netlink消息时会遍历并筛选对应的netlink回应，然后调用data_cb回调进行处理 */
        err = mnl_cb_run2(nlg->buf, err, nlg->seq, nlg->portid,
                  data_cb, data, mnlg_cb_array, MNL_ARRAY_SIZE(mnlg_cb_array));
    } while (err > 0);
    
    return err;
}

static int get_family_id_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
	/* mnl_attr_get_type 返回该属性的类型，这里应该为CTRL_ATTR_FAMILY_ID */
    int type = mnl_attr_get_type(attr);

	/* 判断属性类型是否越界，如超出最大属性类型 */
    if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
        return MNL_CB_ERROR;

	/* ??? 没细看 mnl_attr_validate 貌似是判断该属性的数据是否符合u16类型 */
    if (type == CTRL_ATTR_FAMILY_ID &&
        mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
        return MNL_CB_ERROR;
    tb[type] = attr;
    return MNL_CB_OK;
}

static int get_family_id_cb(const struct nlmsghdr *nlh, void *data)
{
    uint16_t *p_id = data;
    struct nlattr *tb[CTRL_ATTR_MAX + 1] = { 0 };

	/* mnl_attr_parse 遍历当前netlink消息所有的属性并调用回调，这里回调为get_family_id_attr_cb */
    mnl_attr_parse(nlh, sizeof(struct genlmsghdr), get_family_id_attr_cb, tb);
    if (!tb[CTRL_ATTR_FAMILY_ID])
        return MNL_CB_ERROR;
	/* 剥除最后的attribute头(struct nlattr)，获取数据，这里为family_name对应的family_id */
    *p_id = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
    return MNL_CB_OK;
}

struct mnlg_socket *mnlg_socket_open(const char *family_name, uint8_t version)
{
    struct mnlg_socket *nlg;
    struct nlmsghdr *nlh;
    int err;

    nlg = malloc(sizeof(*nlg));
    if (!nlg)
        return NULL;

    err = -ENOMEM;
    nlg->buf = malloc(MNL_SOCKET_BUFFER_SIZE);
    if (!nlg->buf)
        goto err_buf_alloc;

    nlg->nl = mnl_socket_open(NETLINK_GENERIC);
    if (!nlg->nl) {
        err = -errno;
        goto err_mnl_socket_open;
    }

    if (mnl_socket_bind(nlg->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        err = -errno;
        goto err_mnl_socket_bind;
    }

    /* 使用MNL_SOCKET_AUTOPID从内核获得nl_pid需要调用mnl_socket_get_portid */
	/* 一般返回值是进程ID，但当一个进程开启多个netlink socket时返回的就不一定了 */
    nlg->portid = mnl_socket_get_portid(nlg->nl);

	/* 向内核查询内核给family_name分配的id */
    nlh = __mnlg_msg_prepare(nlg, CTRL_CMD_GETFAMILY,
                 NLM_F_REQUEST | NLM_F_ACK, GENL_ID_CTRL, 1);
	/* 添加一个字符串类型的attribute */
    mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, family_name);

	/* 向内核发送 */
    if (mnlg_socket_send(nlg, nlh) < 0) {
        err = -errno;
        goto err_mnlg_socket_send;
    }
    errno = 0;
	/* 接收内核netlink消息并调用get_family_id_cb回调来解析family_name的id */
    if (mnlg_socket_recv_run(nlg, get_family_id_cb, &nlg->id) < 0) {
        errno = errno == ENOENT ? EPROTONOSUPPORT : errno;
        err = errno ? -errno : -ENOSYS;
        goto err_mnlg_socket_recv_run;
    }

    nlg->version = version;
    errno = 0;
    return nlg;

err_mnlg_socket_recv_run:
err_mnlg_socket_send:
err_mnl_socket_bind:
    mnl_socket_close(nlg->nl);
err_mnl_socket_open:
    free(nlg->buf);
err_buf_alloc:
    free(nlg);
    errno = -err;
    return NULL;
}

void mnlg_socket_close(struct mnlg_socket *nlg)
{
    mnl_socket_close(nlg->nl);
    free(nlg->buf);
    free(nlg);
}
