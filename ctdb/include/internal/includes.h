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

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#endif /* _CTDB_INCLUDES_H */
