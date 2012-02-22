#include "external-agent.h"
#include "tdb1_private.h"

enum agent_return external_agent_needs_rec(struct tdb_context *tdb)
{
	if (tdb->flags & TDB_VERSION1)
		return tdb1_needs_recovery(tdb) ? SUCCESS : FAILED;
	else
		return tdb_needs_recovery(tdb) ? SUCCESS : FAILED;
}
