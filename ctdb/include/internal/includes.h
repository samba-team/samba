#ifndef _CTDB_INCLUDES_H
#define _CTDB_INCLUDES_H

#define HAVE_UNIXSOCKET 1

#include "replace.h"
#include "talloc.h"
#include "system/wait.h"
#include "system/network.h"
#include "tdb.h"
#include "idtree.h"
#include "ctdb_client.h"

/* Allow use of deprecated function tevent_loop_allow_nesting() */
#define TEVENT_DEPRECATED
/* Saves ctdb from massive churn. */
#define TEVENT_COMPAT_DEFINES 1

#include "tevent.h"

extern int LogLevel;
extern int this_log_level;

enum debug_level { 
	DEBUG_EMERG   = -3, 
	DEBUG_ALERT   = -2, 
	DEBUG_CRIT    = -1,
	DEBUG_ERR     =  0,
	DEBUG_WARNING =  1,
	DEBUG_NOTICE  =  2,	
	DEBUG_INFO    =  3,
	DEBUG_DEBUG   =  4,
};

#define DEBUGLVL(lvl) ((lvl) <= LogLevel)
#define DEBUG(lvl, x) do { this_log_level = (lvl); if ((lvl) < DEBUG_DEBUG) { log_ringbuffer x; } if ((lvl) <= LogLevel) { do_debug x; }} while (0)
#define DEBUGADD(lvl, x) do { if ((lvl) <= LogLevel) { this_log_level = (lvl); do_debug_add x; }} while (0)

#define _PUBLIC_
#define _NORETURN_
#define _PURE_

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

struct timeval timeval_zero(void);
bool timeval_is_zero(const struct timeval *tv);
struct timeval timeval_current(void);
struct timeval timeval_set(uint32_t secs, uint32_t usecs);
int timeval_compare(const struct timeval *tv1, const struct timeval *tv2);
struct timeval timeval_until(const struct timeval *tv1,
			     const struct timeval *tv2);
_PUBLIC_ struct timeval timeval_current_ofs(uint32_t secs, uint32_t usecs);
double timeval_elapsed(struct timeval *tv);
double timeval_delta(struct timeval *tv2, struct timeval *tv);
char **file_lines_load(const char *fname, int *numlines, TALLOC_CTX *mem_ctx);
char *hex_encode_talloc(TALLOC_CTX *mem_ctx, const unsigned char *buff_in, size_t len);
uint8_t *hex_decode_talloc(TALLOC_CTX *mem_ctx, const char *hex_in, size_t *len);
_PUBLIC_ const char **str_list_add(const char **list, const char *s);
_PUBLIC_ int set_blocking(int fd, bool set);

#include "lib/util/debug.h"
#include "lib/util/util.h"

#endif /* _CTDB_INCLUDES_H */
