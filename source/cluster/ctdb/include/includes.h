#define HAVE_UNIXSOCKET 1

#include "replace.h"
#include "talloc.h"
#include "tdb.h"
#include "idtree.h"
#include "ctdb.h"
#include "lib/util/debug.h"

typedef bool BOOL;

#define True 1
#define False 0

extern int LogLevel;

#define DEBUG(lvl, x) if ((lvl) <= LogLevel) (do_debug x)

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
double timeval_elapsed(struct timeval *tv);
char **file_lines_load(const char *fname, int *numlines, TALLOC_CTX *mem_ctx);
char *hex_encode(TALLOC_CTX *mem_ctx, const unsigned char *buff_in, size_t len);
_PUBLIC_ const char **str_list_add(const char **list, const char *s);
_PUBLIC_ int set_blocking(int fd, bool set);

