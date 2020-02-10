/*
   CTDB DB test tool

   Copyright (C) Martin Schwenke  2019

   Parts based on ctdb.c, event_tool.c:

   Copyright (C) Amitay Isaacs  2015, 2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"
#include "system/time.h"

#include <ctype.h>
#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/sys_rw.h"
#include "lib/util/util.h"
#include "lib/tdb_wrap/tdb_wrap.h"

#include "common/cmdline.h"
#include "common/logging.h"
#include "common/path.h"
#include "common/event_script.h"
#include "common/system_socket.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"
#include "protocol/protocol_util.h"

#include "client/client.h"
#include "client/client_sync.h"

struct tdb_context *client_db_tdb(struct ctdb_db_context *db);

#define TIMEOUT()	tevent_timeval_current_ofs(ctx->timelimit, 0)

struct db_test_tool_context {
	struct cmdline_context *cmdline;
	struct tevent_context *ev;
	struct ctdb_client_context *client;
	uint32_t destnode;
	uint32_t timelimit;
};

/*
 * If this is ever consolodated into a larger test tool then these
 * forward declarations can be moved to an include file
 */
int db_test_tool_init(TALLOC_CTX *mem_ctx,
		      const char *prog,
		      struct poptOption *options,
		      int argc,
		      const char **argv,
		      bool parse_options,
		      struct db_test_tool_context **result);
int db_test_tool_run(struct db_test_tool_context *ctx, int *result);

static int db_test_get_lmaster(TALLOC_CTX *mem_ctx,
			       int argc,
			       const char **argv,
			       void *private_data)
{
	struct db_test_tool_context *ctx = talloc_get_type_abort(
		private_data, struct db_test_tool_context);
	struct ctdb_vnn_map *vnnmap;
	TDB_DATA key;
	uint32_t idx, lmaster;
	unsigned int hash;
	int ret = 0;

	if (argc != 1) {
		cmdline_usage(ctx->cmdline, "get-lmaster");
		return 1;
	}

	ret = ctdb_ctrl_getvnnmap(mem_ctx,
				  ctx->ev,
				  ctx->client,
				  CTDB_CURRENT_NODE,
				  TIMEOUT(),
				  &vnnmap);
	if (ret != 0) {
		D_ERR("Control GETVNN_MAP failed, ret=%d\n", ret);
		return ret;
	}

	key.dsize = strlen(argv[0]);
	key.dptr = (uint8_t *)discard_const(argv[0]);

	hash = tdb_jenkins_hash(&key);
	idx =  hash % vnnmap->size;
	lmaster = vnnmap->map[idx];

	printf("%"PRId32"\n", lmaster);

	return 0;
}

static struct ctdb_dbid *db_find(TALLOC_CTX *mem_ctx,
				 struct db_test_tool_context *ctx,
				 struct ctdb_dbid_map *dbmap,
				 const char *db_name)
{
	struct ctdb_dbid *db = NULL;
	const char *name;
	unsigned int i;
	int ret;

	for (i=0; i<dbmap->num; i++) {
		ret = ctdb_ctrl_get_dbname(mem_ctx,
					   ctx->ev,
					   ctx->client,
					   ctx->destnode,
					   TIMEOUT(),
					   dbmap->dbs[i].db_id,
					   &name);
		if (ret != 0) {
			return NULL;
		}

		if (strcmp(db_name, name) == 0) {
			talloc_free(discard_const(name));
			db = &dbmap->dbs[i];
			break;
		}
	}

	return db;
}

static bool db_exists(TALLOC_CTX *mem_ctx,
		      struct db_test_tool_context *ctx,
		      const char *db_arg,
		      uint32_t *db_id,
		      const char **db_name,
		      uint8_t *db_flags)
{
	struct ctdb_dbid_map *dbmap;
	struct ctdb_dbid *db = NULL;
	uint32_t id = 0;
	const char *name = NULL;
	unsigned int i;
	int ret = 0;

	ret = ctdb_ctrl_get_dbmap(mem_ctx,
				  ctx->ev,
				  ctx->client,
				  ctx->destnode,
				  TIMEOUT(),
				  &dbmap);
	if (ret != 0) {
		return false;
	}

	if (strncmp(db_arg, "0x", 2) == 0) {
		id = smb_strtoul(db_arg, NULL, 0, &ret, SMB_STR_STANDARD);
		if (ret != 0) {
			return false;
		}
		for (i=0; i<dbmap->num; i++) {
			if (id == dbmap->dbs[i].db_id) {
				db = &dbmap->dbs[i];
				break;
			}
		}
	} else {
		name = db_arg;
		db = db_find(mem_ctx, ctx, dbmap, name);
	}

	if (db == NULL) {
		fprintf(stderr, "No database matching '%s' found\n", db_arg);
		return false;
	}

	if (name == NULL) {
		ret = ctdb_ctrl_get_dbname(mem_ctx,
					   ctx->ev,
					   ctx->client,
					   ctx->destnode,
					   TIMEOUT(),
					   id,
					   &name);
		if (ret != 0) {
			return false;
		}
	}

	if (db_id != NULL) {
		*db_id = db->db_id;
	}
	if (db_name != NULL) {
		*db_name = talloc_strdup(mem_ctx, name);
	}
	if (db_flags != NULL) {
		*db_flags = db->flags;
	}
	return true;
}

static int db_test_fetch_local_delete(TALLOC_CTX *mem_ctx,
				      int argc,
				      const char **argv,
				      void *private_data)
{
	struct db_test_tool_context *ctx = talloc_get_type_abort(
		private_data, struct db_test_tool_context);
	struct ctdb_db_context *db = NULL;
	struct ctdb_record_handle *h = NULL;
	struct tdb_context *tdb;
	struct ctdb_ltdb_header header;
	const char *db_name;
	TDB_DATA key, data;
	uint32_t db_id;
	uint8_t db_flags;
	size_t len;
	uint8_t *buf;
	size_t np;
	int ret;

	if (argc != 2) {
		cmdline_usage(ctx->cmdline, "fetch-local-delete");
		return 1;
	}

	if (! db_exists(mem_ctx, ctx, argv[0], &db_id, &db_name, &db_flags)) {
		return ENOENT;
	}

	if (db_flags & (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		D_ERR("DB %s is not a volatile database\n", db_name);
		return EINVAL;
	}

	ret = ctdb_attach(ctx->ev,
			  ctx->client,
			  TIMEOUT(),
			  db_name,
			  db_flags,
			  &db);
	if (ret != 0) {
		D_ERR("Failed to attach to DB %s\n", db_name);
		return ret;
	}

	key.dsize = strlen(argv[1]);
	key.dptr = (uint8_t *)discard_const(argv[1]);

	ret = ctdb_fetch_lock(mem_ctx,
			      ctx->ev,
			      ctx->client,
			      db,
			      key,
			      false,
			      &h,
			      &header,
			      NULL);
	if (ret != 0) {
		D_ERR("Failed to fetch record for key %s\n", argv[1]);
		goto done;
	}

	len = ctdb_ltdb_header_len(&header);
	buf = talloc_size(mem_ctx, len);
	if (buf == NULL) {
		D_ERR("Memory allocation error\n");
		ret = ENOMEM;
		goto done;
	}

	ctdb_ltdb_header_push(&header, buf, &np);

	data.dsize = np;
	data.dptr = buf;

	tdb = client_db_tdb(db);

	ret = tdb_store(tdb, key, data, TDB_REPLACE);
	TALLOC_FREE(buf);
	if (ret != 0) {
		D_ERR("fetch_lock delete: %s tdb_store failed, %s\n",
		      db_name,
		      tdb_errorstr(tdb));
	}

done:
	TALLOC_FREE(h);

	return ret;
}

#define ISASCII(x) (isprint(x) && ! strchr("\"\\", (x)))

static void dump(const char *name, uint8_t *dptr, size_t dsize)
{
	size_t i;

	fprintf(stdout, "%s(%zu) = \"", name, dsize);
	for (i = 0; i < dsize; i++) {
		if (ISASCII(dptr[i])) {
			fprintf(stdout, "%c", dptr[i]);
		} else {
			fprintf(stdout, "\\%02X", dptr[i]);
		}
	}
	fprintf(stdout, "\"\n");
}

static void dump_ltdb_header(struct ctdb_ltdb_header *header)
{
	fprintf(stdout, "dmaster: %u\n", header->dmaster);
	fprintf(stdout, "rsn: %" PRIu64 "\n", header->rsn);
	fprintf(stdout, "flags: 0x%08x", header->flags);
	if (header->flags & CTDB_REC_FLAG_MIGRATED_WITH_DATA) {
		fprintf(stdout, " MIGRATED_WITH_DATA");
	}
	if (header->flags & CTDB_REC_FLAG_VACUUM_MIGRATED) {
		fprintf(stdout, " VACUUM_MIGRATED");
	}
	if (header->flags & CTDB_REC_FLAG_AUTOMATIC) {
		fprintf(stdout, " AUTOMATIC");
	}
	if (header->flags & CTDB_REC_RO_HAVE_DELEGATIONS) {
		fprintf(stdout, " RO_HAVE_DELEGATIONS");
	}
	if (header->flags & CTDB_REC_RO_HAVE_READONLY) {
		fprintf(stdout, " RO_HAVE_READONLY");
	}
	if (header->flags & CTDB_REC_RO_REVOKING_READONLY) {
		fprintf(stdout, " RO_REVOKING_READONLY");
	}
	if (header->flags & CTDB_REC_RO_REVOKE_COMPLETE) {
		fprintf(stdout, " RO_REVOKE_COMPLETE");
	}
	fprintf(stdout, "\n");

}

static int db_test_local_lock(TALLOC_CTX *mem_ctx,
			      int argc,
			      const char **argv,
			      void *private_data)
{
	struct db_test_tool_context *ctx = talloc_get_type_abort(
		private_data, struct db_test_tool_context);
	struct ctdb_db_context *db;
	const char *db_name;
	int pipefd[2];
	TDB_DATA key;
	uint32_t db_id;
	uint8_t db_flags;
	pid_t pid;
	int ret;

	if (argc != 2) {
		cmdline_usage(ctx->cmdline, "local-lock");
		return 1;
	}


	if (! db_exists(mem_ctx, ctx, argv[0], &db_id, &db_name, &db_flags)) {
		D_ERR("DB %s not attached\n", db_name);
		return 1;
	}

	if (db_flags & (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		D_ERR("DB %s is not a volatile database\n", db_name);
		return 1;
	}

	ret = ctdb_attach(ctx->ev,
			  ctx->client,
			  TIMEOUT(),
			  db_name,
			  db_flags,
			  &db);
	if (ret != 0) {
		D_ERR("Failed to attach to DB %s\n", db_name);
		return 1;
	}

	ret = pipe(pipefd);
	if (ret != 0) {
		DBG_ERR("Failed to create pipe\n");
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		DBG_ERR("Failed to fork()\n");
		return 1;
	}

	if (pid != 0) {
		ssize_t nread;
		int status;

		close(pipefd[1]);

		nread = sys_read(pipefd[0], &status, sizeof(status));
		if (nread < 0 || (size_t)nread != sizeof(status)) {
			status = EINVAL;
		}

		if (status == 0) {
			printf("OK %d\n", pid);
		} else {
			printf("FAIL %d\n", status);
		}
		fflush(stdout);

		return status;
	}

	close(pipefd[0]);

	key.dsize = strlen(argv[1]);
	key.dptr = (uint8_t *)discard_const(argv[1]);

	ret = tdb_chainlock(client_db_tdb(db), key);
	if (ret != 0) {
		D_ERR("Failed to lock chain for key %s\n", argv[1]);
		goto fail;
	}

	sys_write(pipefd[1], &ret, sizeof(ret));

	fclose(stdin);
	fclose(stdout);
	fclose(stderr);

	/* Hold the lock- the caller should SIGTERM to release the lock */
	sleep(120);
	exit(1);

fail:
	sys_write(pipefd[1], &ret, sizeof(ret));
	return ret;
}

static int db_test_local_read(TALLOC_CTX *mem_ctx,
			      int argc,
			      const char **argv,
			      void *private_data)
{
	struct db_test_tool_context *ctx = talloc_get_type_abort(
		private_data, struct db_test_tool_context);
	struct ctdb_db_context *db;
	struct ctdb_ltdb_header header;
	const char *db_name;
	TDB_DATA key, data;
	uint32_t db_id;
	uint8_t db_flags;
	size_t np;
	int ret;

	if (argc != 2) {
		cmdline_usage(ctx->cmdline, "local-read");
		return 1;
	}

	if (! db_exists(mem_ctx, ctx, argv[0], &db_id, &db_name, &db_flags)) {
		return ENOENT;
	}

	if (db_flags & (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		D_ERR("DB %s is not a volatile database\n", db_name);
		return EINVAL;
	}

	ret = ctdb_attach(ctx->ev,
			  ctx->client,
			  TIMEOUT(),
			  db_name,
			  db_flags,
			  &db);
	if (ret != 0) {
		D_ERR("Failed to attach to DB %s\n", db_name);
		return ret;
	}

	key.dsize = strlen(argv[1]);
	key.dptr = (uint8_t *)discard_const(argv[1]);

	data = tdb_fetch(client_db_tdb(db), key);

	if (data.dptr == NULL) {
		D_ERR("No record for key %s\n", argv[1]);
		return 1;
	}

	if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
		D_ERR("Invalid record for key %s\n", argv[1]);
		free(data.dptr);
		return 1;
	}

	ret = ctdb_ltdb_header_pull(data.dptr, data.dsize, &header, &np);
	if (ret != 0) {
		D_ERR("Failed to parse header from data\n");
		free(data.dptr);
		return 1;
	}

	dump_ltdb_header(&header);
	dump("data", data.dptr + np, data.dsize - np);

	free(data.dptr);

	return 0;
}

static int db_test_vacuum(TALLOC_CTX *mem_ctx,
			  int argc,
			  const char **argv,
			  void *private_data)
{
	struct db_test_tool_context *ctx = talloc_get_type_abort(
		private_data, struct db_test_tool_context);
	struct ctdb_db_vacuum db_vacuum;
	struct ctdb_req_control request;
	struct ctdb_reply_control *reply;
	const char *db_arg;
	uint32_t db_id;
	const char *db_name;
	uint8_t db_flags;
	int ret = 0;

	if (argc != 1 && argc != 2) {
		cmdline_usage(ctx->cmdline, "vacuum");
		return 1;
	}

	db_arg = argv[0];

	db_vacuum.full_vacuum_run = false;
	if (argc == 2) {
		if (strcmp(argv[1], "full") == 0) {
			db_vacuum.full_vacuum_run = true;
		} else {
			cmdline_usage(ctx->cmdline, "vacuum");
			return 1;
		}
	}

	if (! db_exists(mem_ctx, ctx, db_arg, &db_id, &db_name, &db_flags)) {
		return ENOENT;
	}

	if (db_flags & (CTDB_DB_FLAGS_PERSISTENT | CTDB_DB_FLAGS_REPLICATED)) {
		D_ERR("DB %s is not a volatile database\n", db_name);
		return EINVAL;
	}

	db_vacuum.db_id = db_id;

	ctdb_req_control_db_vacuum(&request, &db_vacuum);

	ret = ctdb_client_control(mem_ctx,
				  ctx->ev,
				  ctx->client,
				  ctx->destnode,
				  TIMEOUT(),
				  &request,
				  &reply);
	if (ret != 0) {
		D_ERR("Control DB_VACUUM failed to node %u, ret=%d\n",
		      ctx->destnode,
		      ret);
		return ret;
	}


	ret = ctdb_reply_control_db_vacuum(reply);
	if (ret != 0) {
		D_ERR("Control DB_VACUUM failed, ret=%d\n", ret);
		return ret;
	}

	return 0;
}

struct cmdline_command db_test_commands[] = {
	{
		.name     = "get-lmaster",
		.fn       = db_test_get_lmaster,
		.msg_help = "Print lmaster for key",
		.msg_args = "<key>"
	},
	{
		.name     = "fetch-local-delete",
		.fn       = db_test_fetch_local_delete,
		.msg_help = "Fetch record and delete from local database",
		.msg_args = "<dbname|dbid> <key>"
	},
	{
		.name     = "local-lock",
		.fn       = db_test_local_lock,
		.msg_help = "Lock a record in a local database",
		.msg_args = "<dbname|dbid> <key>"
	},
	{
		.name     = "local-read",
		.fn       = db_test_local_read,
		.msg_help = "Read a record from local database",
		.msg_args = "<dbname|dbid> <key>"
	},
	{
		.name     = "vacuum",
		.fn       = db_test_vacuum,
		.msg_help = "Vacuum a database",
		.msg_args = "<dbname|dbid> [full]"
	},
	CMDLINE_TABLEEND
};

int db_test_tool_init(TALLOC_CTX *mem_ctx,
		      const char *prog,
		      struct poptOption *options,
		      int argc,
		      const char **argv,
		      bool parse_options,
		      struct db_test_tool_context **result)
{
	struct db_test_tool_context *ctx;
	int ret;

	ctx = talloc_zero(mem_ctx, struct db_test_tool_context);
	if (ctx == NULL) {
		D_ERR("Memory allocation error\n");
		return ENOMEM;
	}

	ret = cmdline_init(mem_ctx,
			   prog,
			   options,
			   NULL,
			   db_test_commands,
			   &ctx->cmdline);
	if (ret != 0) {
		D_ERR("Failed to initialize cmdline, ret=%d\n", ret);
		talloc_free(ctx);
		return ret;
	}

	ret = cmdline_parse(ctx->cmdline, argc, argv, parse_options);
	if (ret != 0) {
		cmdline_usage(ctx->cmdline, NULL);
		talloc_free(ctx);
		return ret;
	}

	*result = ctx;
	return 0;
}

int db_test_tool_run(struct db_test_tool_context *ctx, int *result)
{
	char *ctdb_socket;
	int ret;

	ctx->ev = tevent_context_init(ctx);
	if (ctx->ev == NULL) {
		D_ERR("Failed to initialize tevent\n");
		return ENOMEM;
	}

	ctdb_socket = path_socket(ctx, "ctdbd");
	if (ctdb_socket == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return ENOMEM;
	}

	ret = ctdb_client_init(ctx, ctx->ev, ctdb_socket, &ctx->client);
	if (ret != 0) {
		D_ERR("Failed to connect to CTDB daemon (%s)\n", ctdb_socket);
		return ret;
	}

	ret = cmdline_run(ctx->cmdline, ctx, result);
	return ret;
}

#ifdef CTDB_DB_TEST_TOOL

static struct {
	const char *debug;
	int destnode;
	int timelimit;
} db_test_data = {
	.debug = "ERROR",
	.destnode = CTDB_CURRENT_NODE,
	.timelimit = 60,
};

struct poptOption db_test_options[] = {
	{
		.longName   = "debug",
		.shortName  = 'd',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &db_test_data.debug,
		.val        = 0,
		.descrip    = "debug level",
		.argDescrip = "ERROR|WARNING|NOTICE|INFO|DEBUG"
	},
	{
		.longName   = "node",
		.shortName  = 'n',
		.argInfo    = POPT_ARG_INT,
		.arg        = &db_test_data.destnode,
		.val        = 0,
		.descrip    = "node number",
		.argDescrip = "NUM"
	},
	{
		.longName   = "timelimit",
		.shortName  = 't',
		.argInfo    = POPT_ARG_INT,
		.arg        = &db_test_data.timelimit,
		.val        = 0,
		.descrip    = "control time limit",
		.argDescrip = "SECONDS"
	},
	POPT_TABLEEND
};

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	struct db_test_tool_context *ctx;
	int ret, result = 0;
	int level;
	bool ok;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	ret = db_test_tool_init(mem_ctx,
				"ctdb-db-test",
				db_test_options,
				argc,
				argv,
				true,
				&ctx);
	if (ret != 0) {
		talloc_free(mem_ctx);
		exit(1);
	}

	setup_logging("ctdb-db-test", DEBUG_STDERR);
	ok = debug_level_parse(db_test_data.debug, &level);
	if (!ok) {
		level = DEBUG_ERR;
	}
	debuglevel_set(level);

	ctx->destnode = db_test_data.destnode;
	ctx->timelimit = db_test_data.timelimit;

	ret = db_test_tool_run(ctx, &result);
	if (ret != 0) {
		result = ret;
	}

	talloc_free(mem_ctx);
	exit(result);
}

#endif /* CTDB_DB_TEST_TOOL */
