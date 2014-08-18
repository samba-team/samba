#ifndef _CTDB_INCLUDES_H
#define _CTDB_INCLUDES_H

#include "replace.h"
#include "talloc.h"
#include "system/wait.h"
#include "system/network.h"
#include "tdb.h"
#include "ctdb_client.h"

/* Allow use of deprecated function tevent_loop_allow_nesting() */
#define TEVENT_DEPRECATED
/* Saves ctdb from massive churn. */
#define TEVENT_COMPAT_DEFINES 1

#include "tevent.h"

#include "ctdb_logging.h"

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#endif /* _CTDB_INCLUDES_H */
