#include "../common/tdb_private.h"
#include "../common/io.c"
#include "../common/tdb.c"
#include "../common/lock.c"
#include "../common/freelist.c"
#include "../common/traverse.c"
#include "../common/transaction.c"
#include "../common/error.c"
#include "../common/open.c"
#include "../common/check.c"
#include "../common/hash.c"
#include "../common/rescue.c"
#include "../common/mutex.c"
#include "tap-interface.h"
#include <stdlib.h>
#include "logging.h"

#define NUM 20

/* Binary searches are deceptively simple: easy to screw up! */
int main(int argc, char *argv[])
{
	unsigned int i, j, n;
	struct found f[NUM+1];
	struct found_table table;

	/* Set up array for searching. */
	for (i = 0; i < NUM+1; i++) {
		f[i].head = i * 3;
	}
	table.arr = f;

	for (i = 0; i < NUM; i++) {
		table.num = i;
		for (j = 0; j < (i + 2) * 3; j++) {
			n = find_entry(&table, j);
			ok1(n <= i);

			/* If we were searching for something too large... */
			if (j > i*3)
				ok1(n == i);
			else {
				/* It must give us something after j */
				ok1(f[n].head >= j);
				ok1(n == 0 || f[n-1].head < j);
			}
		}
	}

	return exit_status();
}
