#include <sqlite3.h>

struct lsqlite3_private {
	char **         options;
	const char *    basedn;
        sqlite3 *       sqlite;
        int             lock_count;
};

void
lsqlite3_base160(unsigned long val,
                 unsigned char result[5]);

char *
lsqlite3_base160Next(char base160[]);
