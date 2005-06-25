#include <sqlite3.h>

struct lsqlite3_private {
	char **         options;
        sqlite3 *       sqlite;
        int             lock_count;
};
