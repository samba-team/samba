#include "replace.h"
#include "system/filesys.h"
#include "system/time.h"
#include "tdb.h"
#include "ldb_module.h"

TDB_DATA ltdb_key(struct ldb_module *module, struct ldb_dn *dn);
int ltdb_err_map(enum TDB_ERROR tdb_code);

struct tdb_context *ltdb_wrap_open(TALLOC_CTX *mem_ctx,
				   const char *path, int hash_size, int tdb_flags,
				   int open_flags, mode_t mode,
				   struct ldb_context *ldb);
int ltdb_connect(struct ldb_context *ldb, const char *url,
		 unsigned int flags, const char *options[],
		 struct ldb_module **_module);
