#include "tdb2-source.h"
#include "tap-interface.h"

int main(int argc, char *argv[])
{
	enum TDB_ERROR e;
	plan_tests(TDB_ERR_RDONLY*-1 + 2);

	for (e = TDB_SUCCESS; e >= TDB_ERR_RDONLY; e--) {
		switch (e) {
		case TDB_SUCCESS:
			ok1(!strcmp(tdb_errorstr(e),
				    "Success"));
			break;
		case TDB_ERR_IO:
			ok1(!strcmp(tdb_errorstr(e),
				    "IO Error"));
			break;
		case TDB_ERR_LOCK:
			ok1(!strcmp(tdb_errorstr(e),
				    "Locking error"));
			break;
		case TDB_ERR_OOM:
			ok1(!strcmp(tdb_errorstr(e),
				    "Out of memory"));
			break;
		case TDB_ERR_EXISTS:
			ok1(!strcmp(tdb_errorstr(e),
				    "Record exists"));
			break;
		case TDB_ERR_EINVAL:
			ok1(!strcmp(tdb_errorstr(e),
				    "Invalid parameter"));
			break;
		case TDB_ERR_NOEXIST:
			ok1(!strcmp(tdb_errorstr(e),
				    "Record does not exist"));
			break;
		case TDB_ERR_RDONLY:
			ok1(!strcmp(tdb_errorstr(e),
				    "write not permitted"));
			break;
		case TDB_ERR_CORRUPT:
			ok1(!strcmp(tdb_errorstr(e),
				    "Corrupt database"));
			break;
		}
	}
	ok1(!strcmp(tdb_errorstr(e), "Invalid error code"));

	return exit_status();
}
