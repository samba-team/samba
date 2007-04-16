#define HAVE_UNIXSOCKET 1

#include "replace.h"
#include "talloc.h"
#include "tdb.h"
#include "idtree.h"
#include "ctdb.h"
#include "lib/util/dlinklist.h"

typedef bool BOOL;

#define True 1
#define False 0

#define LogLevel 0

#define DEBUG(lvl, x) if ((lvl) <= LogLevel) (printf x)

#define _PUBLIC_

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
char **file_lines_load(const char *fname, int *numlines, TALLOC_CTX *mem_ctx);

