#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "tdb.h"

/* a tdb tool for manipulating a tdb database */

static TDB_CONTEXT *tdb;

static void help(void)
{
	printf("
tdbtool: 
  create    dbname     : create a database
  open      dbname     : open an existing database
  erase                : erase the database
  dump                 : dump the database as strings
  insert    key  data  : insert a record
  store     key  data  : store a record (replace)
  show      key        : show a record by key
  delete    key        : delete a record by key
");
}

static void terror(char *why)
{
	printf("%s\n", why);
}

static void create_tdb(void)
{
	char *tok = strtok(NULL, " ");
	if (!tok) {
		help();
		return;
	}
	if (tdb) tdb_close(tdb);
	tdb = tdb_open(tok, 0, O_RDWR | O_CREAT | O_TRUNC, 0600);
}

static void open_tdb(void)
{
	char *tok = strtok(NULL, " ");
	if (!tok) {
		help();
		return;
	}
	if (tdb) tdb_close(tdb);
	tdb = tdb_open(tok, 0, O_RDWR, 0600);
}

static void insert_tdb(void)
{
	char *k = strtok(NULL, " ");
	char *d = strtok(NULL, " ");
	TDB_DATA key, dbuf;

	if (!k || !d) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k);
	dbuf.dptr = d;
	dbuf.dsize = strlen(d);

	if (tdb_store(tdb, key, dbuf, TDB_INSERT) == -1) {
		terror("insert failed");
	}
}

static void store_tdb(void)
{
	char *k = strtok(NULL, " ");
	char *d = strtok(NULL, " ");
	TDB_DATA key, dbuf;

	if (!k || !d) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k);
	dbuf.dptr = d;
	dbuf.dsize = strlen(d);

	if (tdb_store(tdb, key, dbuf, TDB_REPLACE) == -1) {
		terror("store failed");
	}
}

static void show_tdb(void)
{
	char *k = strtok(NULL, " ");
	TDB_DATA key, dbuf;

	if (!k) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k);

	dbuf = tdb_fetch(tdb, key);
	if (!dbuf.dptr) terror("fetch failed");
	printf("%s : %*.*s\n", k, (int)dbuf.dsize, (int)dbuf.dsize, dbuf.dptr);
}

static void delete_tdb(void)
{
	char *k = strtok(NULL, " ");
	TDB_DATA key;

	if (!k) {
		help();
		return;
	}

	key.dptr = k;
	key.dsize = strlen(k);

	if (tdb_delete(tdb, key) != 0) {
		terror("delete failed");
	}
}

static int print_rec(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf)
{
	printf("%*.*s : %*.*s\n", 
	       (int)key.dsize, (int)key.dsize, key.dptr, 
	       (int)dbuf.dsize, (int)dbuf.dsize, dbuf.dptr);
	return 0;
}

static int total_bytes;

static int traverse_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf)
{
	total_bytes += dbuf.dsize;
	return 0;
}

static void info_tdb(void)
{
	int count;
	total_bytes = 0;
	count = tdb_traverse(tdb, traverse_fn);
	printf("%d records totalling %d bytes\n", count, total_bytes);
}

int main(int argc, char *argv[])
{
	char *line;
	char *tok;
	
	while ((line=readline("tdb> "))) {
		tok = strtok(line," ");
		if (strcmp(tok,"create") == 0) {
			create_tdb();
			continue;
		} else if (strcmp(tok,"open") == 0) {
			open_tdb();
			continue;
		}

		/* all the rest require a open database */
		if (!tdb) {
			terror("database not open");
			help();
			continue;
		}

		if (strcmp(tok,"insert") == 0) {
			insert_tdb();
		} else if (strcmp(tok,"store") == 0) {
			store_tdb();
		} else if (strcmp(tok,"show") == 0) {
			show_tdb();
		} else if (strcmp(tok,"erase") == 0) {
			tdb_traverse(tdb, tdb_delete);
		} else if (strcmp(tok,"delete") == 0) {
			delete_tdb();
		} else if (strcmp(tok,"dump") == 0) {
			tdb_traverse(tdb, print_rec);
		} else if (strcmp(tok,"info") == 0) {
			info_tdb();
		} else {
			help();
		}
	}

	if (tdb) tdb_close(tdb);

	return 0;
}
