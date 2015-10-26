#ifndef _CTDB_INCLUDES_H
#define _CTDB_INCLUDES_H

/* Replace must be before broken tdb.h to define bool */
#include "replace.h"
#include "system/wait.h"
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

/* Allow use of deprecated function tevent_loop_allow_nesting() */
#define TEVENT_DEPRECATED
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#include "common/srvid.h"
#include "ctdb_client.h"
#include "ctdb_logging.h"

#endif /* _CTDB_INCLUDES_H */
