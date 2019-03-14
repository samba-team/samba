#include "includes.h"
#include "mdssvc.h"
#include "rpc_server/mdssvc/sparql_parser.tab.h"
#include "rpc_server/mdssvc/mdssvc_tracker.h"

/*
 * Examples:
 *
 * $ ./spotlight2sparql '_kMDItemGroupId=="11"'
 * ...
 * $ ./spotlight2sparql '*=="test*"cwd||kMDItemTextContent=="test*"cwd'
 * ...
 */

int main(int argc, char **argv)
{
	struct sl_tracker_query *tq = NULL;
	bool ok;
	struct sl_query *slq;

	if (argc != 2) {
		printf("usage: %s QUERY\n", argv[0]);
		return 1;
	}

	slq = talloc_zero(NULL, struct sl_query);
	if (slq == NULL) {
		printf("talloc error\n");
		return 1;
	}

	slq->query_string = argv[1];
	slq->path_scope = "/foo/bar";

	tq = talloc_zero(slq, struct sl_tracker_query);
	if (tq == NULL) {
		printf("talloc error\n");
		return 1;
	}
	slq->backend_private = tq;

	ok = map_spotlight_to_sparql_query(slq);
	printf("%s\n", ok ? tq->sparql_query : "*mapping failed*");

	talloc_free(slq);
	return ok ? 0 : 1;
}
