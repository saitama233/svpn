#ifndef _MNLG_H
#define _MNLG_H

#include "common.h"
#ifdef __linux__

#include <libmnl/libmnl.h> /* Ubuntu需要安装libmnl */
#include <linux/genetlink.h> /* CTRL_ATTR_FAMILY_ID */

struct mnlg_socket;

struct nlmsghdr *mnlg_msg_prepare(struct mnlg_socket *nlg, uint8_t cmd,
                          uint16_t flags);
int mnlg_socket_send(struct mnlg_socket *nlg, const struct nlmsghdr *nlh);
int mnlg_socket_recv_run(struct mnlg_socket *nlg, mnl_cb_t data_cb, void *data);
struct mnlg_socket *mnlg_socket_open(const char *family_name, uint8_t version);
void mnlg_socket_close(struct mnlg_socket *nlg);

#endif

#endif
