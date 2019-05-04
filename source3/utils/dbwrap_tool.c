/*
   Samba Unix/Linux CIFS implementation

   low level TDB/CTDB tool using the dbwrap interface

   Copyright (C) 2009 Michael Adam <obnox@samba.org>
   Copyright (C) 2011 Bjoern Baumbach <bb@sernet.de>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "popt_common.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "messages.h"
#include "util_tdb.h"
#include "cmdline_contexts.h"

enum dbwrap_op { OP_FETCH, OP_STORE, OP_DELETE, OP_ERASE, OP_LISTKEYS,
		 OP_EXISTS };

enum dbwrap_type { TYPE_INT32, TYPE_UINT32, TYPE_STRING, TYPE_HEX, TYPE_NONE };

static int dbwrap_tool_fetch_int32(struct db_context *db,
				   const char *keyname,
				   const char *data)
{
	int32_t value;
	NTSTATUS status;

	status = dbwrap_fetch_int32_bystring(db, keyname, &value);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Error fetching int32 from key '%s': %s\n",
			 keyname, nt_errstr(status));
		return -1;
	}
	d_printf("%d\n", value);

	return 0;
}

static int dbwrap_tool_fetch_uint32(struct db_context *db,
				    const char *keyname,
				    const char *data)
{
	uint32_t value;
	NTSTATUS ret;

	ret = dbwrap_fetch_uint32_bystring(db, keyname, &value);
	if (NT_STATUS_IS_OK(ret)) {
		d_printf("%u\n", value);
		return 0;
	} else {
		d_fprintf(stderr, "ERROR: could not fetch uint32 key '%s': "
			  "%s\n", nt_errstr(ret), keyname);
		return -1;
	}
}

static int dbwrap_tool_fetch_string(struct db_context *db,
				    const char *keyname,
				    const char *data)
{
	TDB_DATA tdbdata;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	int ret;

	status = dbwrap_fetch_bystring(db, tmp_ctx, keyname, &tdbdata);
	if (NT_STATUS_IS_OK(status)) {
		d_printf("%-*.*s\n", (int)tdbdata.dsize, (int)tdbdata.dsize,
			 tdbdata.dptr);
		ret = 0;
	} else {
		d_fprintf(stderr, "ERROR: could not fetch string key '%s': "
			  "%s\n", nt_errstr(status), keyname);
		ret = -1;
	}

	talloc_free(tmp_ctx);
	return ret;
}

static int dbwrap_tool_fetch_hex(struct db_context *db,
				 const char *keyname,
				 const char *data)
{
	TDB_DATA tdbdata;
	DATA_BLOB datablob;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	char *hex_string;
	int ret;

	status = dbwrap_fetch_bystring(db, tmp_ctx, keyname, &tdbdata);
	if (NT_STATUS_IS_OK(status)) {
	        datablob.data = tdbdata.dptr;
		datablob.length = tdbdata.dsize;

		hex_string = data_blob_hex_string_upper(tmp_ctx, &datablob);
		if (hex_string == NULL) {
			d_fprintf(stderr, "ERROR: could not get hex string "
				  "from data blob\n");
			ret = -1;
		} else {
			d_printf("%s\n", hex_string);
			ret =  0;
		}
	} else {
		d_fprintf(stderr, "ERROR: could not fetch hex key '%s': "
			  "%s\n", nt_errstr(status), keyname);
		ret = -1;
	}

	talloc_free(tmp_ctx);
	return ret;
}

static int dbwrap_tool_store_int32(struct db_context *db,
				   const char *keyname,
				   const char *data)
{
	NTSTATUS status;
	int32_t value = (int32_t)strtol(data, NULL, 10);

	if (dbwrap_is_persistent(db)) {
		status = dbwrap_trans_store_int32_bystring(db, keyname, value);
	} else {
		status = dbwrap_store_int32_bystring(db, keyname, value);
	}
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "ERROR: could not store int32 key '%s': %s\n",
			  keyname, nt_errstr(status));
		return -1;
	}

	return 0;
}

static int dbwrap_tool_store_uint32(struct db_context *db,
				    const char *keyname,
				    const char *data)
{
	NTSTATUS status;
	uint32_t value = (uint32_t)strtol(data, NULL, 10);

	if (dbwrap_is_persistent(db)) {
		status = dbwrap_trans_store_uint32_bystring(db, keyname, value);
	} else {
		status = dbwrap_store_uint32_bystring(db, keyname, value);
	}
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr,
			  "ERROR: could not store uint32 key '%s': %s\n",
			  keyname, nt_errstr(status));
		return -1;
	}

	return 0;
}

static int dbwrap_tool_store_string(struct db_context *db,
				    const char *keyname,
				    const char *data)
{
	NTSTATUS status;
	TDB_DATA tdbdata;

	tdbdata = string_term_tdb_data(data);

	if (dbwrap_is_persistent(db)) {
		status = dbwrap_trans_store_bystring(db, keyname,
						     tdbdata,
						     TDB_REPLACE);
	} else {
		status = dbwrap_store_bystring(db, keyname,
					      tdbdata,
					      TDB_REPLACE);
	}
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr,
			  "ERROR: could not store string key '%s': %s\n",
			  keyname, nt_errstr(status));
		return -1;
	}

	return 0;
}

static int dbwrap_tool_store_hex(struct db_context *db,
				    const char *keyname,
				    const char *data)
{
	NTSTATUS status;
	DATA_BLOB datablob;
	TDB_DATA tdbdata;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	datablob = strhex_to_data_blob(tmp_ctx, data);
	if(strlen(data) > 0 && datablob.length == 0) {
		d_fprintf(stderr,
			  "ERROR: could not convert hex string to data blob\n"
			  "       Not a valid hex string?\n");
		talloc_free(tmp_ctx);
		return -1;
	}

	tdbdata.dptr = (unsigned char *)datablob.data;
	tdbdata.dsize = datablob.length;

	if (dbwrap_is_persistent(db)) {
		status = dbwrap_trans_store_bystring(db, keyname,
						     tdbdata,
						     TDB_REPLACE);
	} else {
		status = dbwrap_store_bystring(db, keyname,
					       tdbdata,
					       TDB_REPLACE);
	}
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr,
			  "ERROR: could not store string key '%s': %s\n",
			  keyname, nt_errstr(status));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

static int dbwrap_tool_delete(struct db_context *db,
			      const char *keyname,
			      const char *data)
{
	NTSTATUS status;

	if (dbwrap_is_persistent(db)) {
		status = dbwrap_trans_delete_bystring(db, keyname);
	} else {
		status = dbwrap_delete_bystring(db, keyname);
	}

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "ERROR deleting record %s : %s\n",
			  keyname, nt_errstr(status));
		return -1;
	}

	return 0;
}

static int dbwrap_tool_exists(struct db_context *db,
			      const char *keyname,
			      const char *data)
{
	bool result;

	result = dbwrap_exists(db, string_term_tdb_data(keyname));

	if (result) {
		d_fprintf(stdout, "Key %s exists\n", keyname);
	} else {
		d_fprintf(stdout, "Key %s does not exist\n", keyname);
	}

	return (result)?0:1;
}

/**
 * dbwrap_tool_erase: erase the whole data base
 * the keyname argument is not used.
 */
static int dbwrap_tool_erase(struct db_context *db,
			     const char *keyname,
			     const char *data)
{
	int ret;

	ret = dbwrap_wipe(db);

	if (ret != 0) {
		d_fprintf(stderr, "ERROR erasing the database\n");
		return -1;
	}

	return 0;
}

static int listkey_fn(struct db_record *rec, void *private_data)
{
	TDB_DATA key = dbwrap_record_get_key(rec);
	size_t length = key.dsize;
	unsigned char *p = (unsigned char *)key.dptr;

	while (length--) {
		if (isprint(*p) && !strchr("\"\\", *p)) {
			d_printf("%c", *p);
		} else {
			d_printf("\\%02X", *p);
		}
		p++;
	}

	d_printf("\n");

	return 0;
}

static int dbwrap_tool_listkeys(struct db_context *db,
				const char *keyname,
				const char *data)
{
	NTSTATUS status;

	status = dbwrap_traverse_read(db, listkey_fn, NULL, NULL);

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "ERROR listing db keys\n");
		return -1;
	}

	return 0;
}

struct dbwrap_op_dispatch_table {
	enum dbwrap_op op;
	enum dbwrap_type type;
	int (*cmd)(struct db_context *db,
		   const char *keyname,
		   const char *data);
};

struct dbwrap_op_dispatch_table dispatch_table[] = {
	{ OP_FETCH,  TYPE_INT32,  dbwrap_tool_fetch_int32 },
	{ OP_FETCH,  TYPE_UINT32, dbwrap_tool_fetch_uint32 },
	{ OP_FETCH,  TYPE_STRING, dbwrap_tool_fetch_string },
	{ OP_FETCH,  TYPE_HEX,    dbwrap_tool_fetch_hex },
	{ OP_STORE,  TYPE_INT32,  dbwrap_tool_store_int32 },
	{ OP_STORE,  TYPE_UINT32, dbwrap_tool_store_uint32 },
	{ OP_STORE,  TYPE_STRING, dbwrap_tool_store_string },
	{ OP_STORE,  TYPE_HEX,    dbwrap_tool_store_hex },
	{ OP_DELETE, TYPE_INT32,  dbwrap_tool_delete },
	{ OP_ERASE,  TYPE_INT32,  dbwrap_tool_erase },
	{ OP_LISTKEYS, TYPE_INT32, dbwrap_tool_listkeys },
	{ OP_EXISTS, TYPE_STRING, dbwrap_tool_exists },
	{ 0, 0, NULL },
};

int main(int argc, const char **argv)
{
	struct tevent_context *evt_ctx;
	struct messaging_context *msg_ctx;
	struct db_context *db;

	uint16_t count;

	const char *dbname;
	const char *opname;
	enum dbwrap_op op;
	const char *keyname = "";
	const char *keytype = "int32";
	enum dbwrap_type type;
	const char *valuestr = "0";
	int persistent = 0;
	int non_persistent = 0;
	int tdb_flags = TDB_DEFAULT;

	TALLOC_CTX *mem_ctx = talloc_stackframe();

	int ret = 1;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		{ "non-persistent", 0, POPT_ARG_NONE, &non_persistent, 0,
		  "treat the database as non-persistent "
		  "(CAVEAT: This mode might wipe your database!)",
		  NULL },
		{ "persistent", 0, POPT_ARG_NONE, &persistent, 0,
		  "treat the database as persistent",
		  NULL },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	poptContext pc;

	smb_init_locale();
	lp_set_cmdline("log level", "0");
	setup_logging(argv[0], DEBUG_STDERR);

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n",
				poptBadOption(pc, 0), poptStrerror(opt));
			goto done;
		}
	}

	/* setup the remaining options for the main program to use */
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		extra_argv++;
		while (extra_argv[extra_argc]) extra_argc++;
	}

	lp_load_global(get_dyn_CONFIGFILE());

	if ((extra_argc < 2) || (extra_argc > 5)) {
		d_fprintf(stderr,
			  "USAGE: %s [options] <database> <op> [<key> [<type> "
			  "[<value>]]]\n"
			  "       ops: fetch, store, delete, exists, "
			  "erase, listkeys\n"
			  "       types: int32, uint32, string, hex\n",
			 argv[0]);
		goto done;
	}

	if ((persistent + non_persistent) != 1) {
		d_fprintf(stderr, "ERROR: you must specify exactly one "
			  "of --persistent and --non-persistent\n");
		goto done;
	}
	if (non_persistent == 1) {
		tdb_flags |= TDB_CLEAR_IF_FIRST;
	}

	dbname = extra_argv[0];
	opname = extra_argv[1];

	if (strcmp(opname, "store") == 0) {
		if (extra_argc != 5) {
			d_fprintf(stderr, "ERROR: operation 'store' requires "
				  "value argument\n");
			goto done;
		}
		valuestr = extra_argv[4];
		keytype = extra_argv[3];
		keyname = extra_argv[2];
		op = OP_STORE;
	} else if (strcmp(opname, "fetch") == 0) {
		if (extra_argc != 4) {
			d_fprintf(stderr, "ERROR: operation 'fetch' requires "
				  "type but not value argument\n");
			goto done;
		}
		op = OP_FETCH;
		keytype = extra_argv[3];
		keyname = extra_argv[2];
	} else if (strcmp(opname, "delete") == 0) {
		if (extra_argc != 3) {
			d_fprintf(stderr, "ERROR: operation 'delete' does "
				  "not allow type nor value argument\n");
			goto done;
		}
		keyname = extra_argv[2];
		op = OP_DELETE;
	} else if (strcmp(opname, "erase") == 0) {
		if (extra_argc != 2) {
			d_fprintf(stderr, "ERROR: operation 'erase' does "
				  "not take a key argument\n");
			goto done;
		}
		op = OP_ERASE;
	} else if (strcmp(opname, "listkeys") == 0) {
		if (extra_argc != 2) {
			d_fprintf(stderr, "ERROR: operation 'listkeys' does "
				  "not take a key argument\n");
			goto done;
		}
		op = OP_LISTKEYS;
	} else if (strcmp(opname, "exists") == 0) {
		if (extra_argc != 3) {
			d_fprintf(stderr, "ERROR: operation 'exists' does "
				  "not allow type nor value argument\n");
			goto done;
		}
		keyname = extra_argv[2];
		op = OP_EXISTS;
		keytype = "string";
	} else {
		d_fprintf(stderr,
			  "ERROR: invalid op '%s' specified\n"
			  "       supported ops: fetch, store, delete, exists, "
			  "erase, listkeys\n",
			  opname);
		goto done;
	}

	if (strcmp(keytype, "int32") == 0) {
		type = TYPE_INT32;
	} else if (strcmp(keytype, "uint32") == 0) {
		type = TYPE_UINT32;
	} else if (strcmp(keytype, "string") == 0) {
		type = TYPE_STRING;
	} else if (strcmp(keytype, "hex") == 0) {
		type = TYPE_HEX;
	} else if (strcmp(keytype, "none") == 0) {
		type = TYPE_NONE;
	} else {
		d_fprintf(stderr, "ERROR: invalid type '%s' specified.\n"
				  "       supported types: int32, uint32, "
				  "string, hex, none\n",
				  keytype);
		goto done;
	}

	evt_ctx = samba_tevent_context_init(mem_ctx);
	if (evt_ctx == NULL) {
		d_fprintf(stderr, "ERROR: could not init event context\n");
		goto done;
	}

	msg_ctx = messaging_init(mem_ctx, evt_ctx);
	if (msg_ctx == NULL) {
		d_fprintf(stderr, "ERROR: could not init messaging context\n");
		goto done;
	}

	switch (op) {
	case OP_FETCH:
	case OP_STORE:
	case OP_DELETE:
	case OP_ERASE:
	case OP_LISTKEYS:
	case OP_EXISTS:
		db = db_open(mem_ctx, dbname, 0, tdb_flags, O_RDWR | O_CREAT,
			     0644, DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
		if (db == NULL) {
			d_fprintf(stderr, "ERROR: could not open dbname\n");
			goto done;
		}
		break;
	default:
		db = NULL;
		break;
	}

	for (count = 0; dispatch_table[count].cmd != NULL; count++) {
		if ((op == dispatch_table[count].op) &&
		    (type == dispatch_table[count].type))
		{
			ret = dispatch_table[count].cmd(db, keyname, valuestr);
			break;
		}
	}

done:
	poptFreeContext(pc);
	TALLOC_FREE(mem_ctx);
	return ret;
}
