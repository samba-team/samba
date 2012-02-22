#include "external-agent.h"
#include "tdb1_private.h"

/* This isn't possible with via the tdb2 API, but this makes it link. */
enum agent_return external_agent_needs_rec(struct tdb_context *tdb)
{
	return FAILED;
}
