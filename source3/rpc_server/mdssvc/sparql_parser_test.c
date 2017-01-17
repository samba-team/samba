#include "includes.h"
#include "mdssvc.h"
#include "rpc_server/mdssvc/sparql_parser.tab.h"

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

	ok = map_spotlight_to_sparql_query(slq);
	printf("%s\n", ok ? slq->sparql_query : "*mapping failed*");

	talloc_free(slq);
	return ok ? 0 : 1;
}
