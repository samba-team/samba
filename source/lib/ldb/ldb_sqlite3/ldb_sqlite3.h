#include <sqlite3.h>

struct lsqlite3_private {
	char **options;
	const char *basedn;
        sqlite3 * sqlite;
        int lock_count;
	int last_rc;
        struct {
                sqlite3_stmt *begin;
                sqlite3_stmt *commit;
                sqlite3_stmt *rollback;
                sqlite3_stmt *newDN;
                sqlite3_stmt *renameDN;
                sqlite3_stmt *deleteDN;
                sqlite3_stmt *newObjectClass;
                sqlite3_stmt *assignObjectClass;
                sqlite3_stmt *newAttributeUseDefaults;
                sqlite3_stmt *newAttribute;
                sqlite3_stmt *addAttrValuePair;
                sqlite3_stmt *replaceAttrValuePairs;
                sqlite3_stmt *deleteAttrValuePairs;
                sqlite3_stmt *insertSubclass;
                sqlite3_stmt *getDNID;
        } queries;
};

void
lsqlite3_base160(unsigned long val,
                 unsigned char result[5]);

char *
lsqlite3_base160Next(char base160[]);
