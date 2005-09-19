#include <sqlite3.h>

struct lsqlite3_private {
	int trans_count;
	char **options;
        sqlite3 *sqlite;
};
