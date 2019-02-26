#ifndef _COMMON_H
#define _COMMON_H

#include <stdint.h> /* int16_t */
#include <inttypes.h>
#include "wrapfile.h"
#include "snet.h"

#if DEBUG
# define dbg_lprintf(fmt, args...) log_printf(__func__, __LINE__, fmt, ##args)
#else
# define dbg_lprintf(fmt, args...) 
#endif

#endif
