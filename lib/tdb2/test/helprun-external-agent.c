#include "external-agent.h"
#include "private.h"

enum agent_return external_agent_needs_rec(struct tdb_context *tdb)
{
	return tdb_needs_recovery(tdb) ? SUCCESS : FAILED;
}
