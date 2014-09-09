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

#include "ctdb_logging.h"

#ifndef _PUBLIC_
#define _PUBLIC_
#endif /* _PUBLIC_ */
#ifndef _NORETURN_
#define _NORETURN_
#endif /* _NORETURN_ */
#ifndef _PURE_
#define _PURE_
#endif /* _PURE_ */

#ifndef ZERO_STRUCT
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif /* ZERO_STRUCT */

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
char **file_lines_load(const char *fname, int *numlines, size_t maxsize, TALLOC_CTX *mem_ctx);
char *hex_encode_talloc(TALLOC_CTX *mem_ctx, const unsigned char *buff_in, size_t len);
_PUBLIC_ int set_blocking(int fd, bool set);

#include "lib/util/debug.h"
#include "lib/util/util.h"

#endif /* _CTDB_INCLUDES_H */
