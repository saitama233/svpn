#ifndef _SVPN_COMPAT_H
#define _SVPN_COMPAT_H

#include <linux/version.h> /* LINUX_VERSION_CODE, KERNEL_VERSION */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
# error "svpn requires Linux >= 4.4.0"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
# include <net/netlink.h>
# include <net/genetlink.h>
# define nlmsg_parse(a, b, c, d, e, f) nlmsg_parse(a, b, c, d, e)
# define nla_parse_nested(a, b, c, d, e) nla_parse_nested(a, b, c, d)
#endif

#include <linux/cache.h> /* __ro_after_init */
/*
 *  * __ro_after_init is used to mark things that are read-only after init (i.e.
 *   * after mark_rodata_ro() has been called). These are effectively read-only,
 *    * but may get written to during init, so can't live in .rodata (via "const"),
 *     */
#ifndef __ro_after_init
# define __ro_after_init __attribute__((__section__(".data..ro_after_init")))
#endif

#endif
