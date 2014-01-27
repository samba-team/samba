/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
 *  Copyright (C) Michael Adam                      2007-2011
 *  Copyright (C) Gregor Beck                       2011
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Implementation of internal registry database functions. */

#include "includes.h"
#include "system/filesys.h"
#include "registry.h"
#include "reg_db.h"
#include "reg_util_internal.h"
#include "reg_parse_internal.h"
#include "reg_backend_db.h"
#include "reg_objects.h"
#include "nt_printing.h"
#include "util_tdb.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/secdesc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

#define REGDB_VERSION_KEYNAME "INFO/version"

static struct db_context *regdb = NULL;
static int regdb_refcount;

static bool regdb_key_exists(struct db_context *db, const char *key);
static WERROR regdb_fetch_keys_internal(struct db_context *db, const char *key,
					struct regsubkey_ctr *ctr);
static bool regdb_store_keys_internal(struct db_context *db, const char *key,
				      struct regsubkey_ctr *ctr);
static int regdb_fetch_values_internal(struct db_context *db, const char* key,
				       struct regval_ctr *values);
static NTSTATUS regdb_store_values_internal(struct db_context *db, const char *key,
					    struct regval_ctr *values);
static WERROR regdb_store_subkey_list(struct db_context *db, const char *parent,
				      const char *key);

static WERROR regdb_create_basekey(struct db_context *db, const char *key);
static WERROR regdb_create_subkey_internal(struct db_context *db,
					   const char *key,
					   const char *subkey);


struct regdb_trans_ctx {
	NTSTATUS (*action)(struct db_context *, void *);
	void *private_data;
};

static NTSTATUS regdb_trans_do_action(struct db_context *db, void *private_data)
{
	NTSTATUS status;
	int32_t version_id;
	struct regdb_trans_ctx *ctx = (struct regdb_trans_ctx *)private_data;

	status = dbwrap_fetch_int32_bystring(db, REGDB_VERSION_KEYNAME,
					     &version_id);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("ERROR: could not fetch registry db version: %s. "
			  "Denying access.\n", nt_errstr(status)));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (version_id != REGDB_CODE_VERSION) {
		DEBUG(0, ("ERROR: changed registry version %d found while "
			  "trying to write to the registry. Version %d "
			  "expected.  Denying access.\n",
			  version_id, REGDB_CODE_VERSION));
		return NT_STATUS_ACCESS_DENIED;
	}

	status = ctx->action(db,  ctx->private_data);
	return status;
}

static WERROR regdb_trans_do(struct db_context *db,
			     NTSTATUS (*action)(struct db_context *, void *),
			     void *private_data)
{
	NTSTATUS status;
	struct regdb_trans_ctx ctx;


	ctx.action = action;
	ctx.private_data = private_data;

	status = dbwrap_trans_do(db, regdb_trans_do_action, &ctx);

	return ntstatus_to_werror(status);
}

/* List the deepest path into the registry.  All part components will be created.*/

/* If you want to have a part of the path controlled by the tdb and part by
   a virtual registry db (e.g. printing), then you have to list the deepest path.
   For example,"HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Print" 
   allows the reg_db backend to handle everything up to 
   "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion" and then we'll hook 
   the reg_printing backend onto the last component of the path (see 
   KEY_PRINTING_2K in include/rpc_reg.h)   --jerry */

static const char *builtin_registry_paths[] = {
	KEY_PRINTING_2K,
	KEY_PRINTING_PORTS,
	KEY_PRINTING,
	KEY_PRINTING "\\Forms",
	KEY_PRINTING "\\Printers",
	KEY_PRINTING "\\Environments\\Windows NT x86\\Print Processors\\winprint",
	KEY_SHARES,
	KEY_EVENTLOG,
	KEY_SMBCONF,
	KEY_PERFLIB,
	KEY_PERFLIB_009,
	KEY_GROUP_POLICY,
	KEY_SAMBA_GROUP_POLICY,
	KEY_GP_MACHINE_POLICY,
	KEY_GP_MACHINE_WIN_POLICY,
	KEY_HKCU,
	KEY_GP_USER_POLICY,
	KEY_GP_USER_WIN_POLICY,
	"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions",
	"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
	KEY_PROD_OPTIONS,
	"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration",
	KEY_TCPIP_PARAMS,
	KEY_NETLOGON_PARAMS,
	KEY_HKU,
	KEY_HKCR,
	KEY_HKPD,
	KEY_HKPT,
	 NULL };

struct builtin_regkey_value {
	const char *path;
	const char *valuename;
	uint32 type;
	union {
		const char *string;
		uint32 dw_value;
	} data;
};

static struct builtin_regkey_value builtin_registry_values[] = {
	{ KEY_PRINTING_PORTS,
		SAMBA_PRINTER_PORT_NAME, REG_SZ, { "" } },
	{ KEY_PRINTING_2K,
		"DefaultSpoolDirectory", REG_SZ, { "C:\\Windows\\System32\\Spool\\Printers" } },
	{ KEY_EVENTLOG,
		"DisplayName", REG_SZ, { "Event Log" } },
	{ KEY_EVENTLOG,
		"ErrorControl", REG_DWORD, { (char*)0x00000001 } },
	{ NULL, NULL, 0, { NULL } }
};

static WERROR create_key_recursive(struct db_context *db,
				   char *path,
				   const char *subkey)
{
	WERROR werr;
	char *p;

	if (subkey == NULL) {
		return WERR_INVALID_PARAM;
	}

	if (path == NULL) {
		return regdb_create_basekey(db, subkey);
	}

	p = strrchr_m(path, '\\');

	if (p == NULL) {
		werr = create_key_recursive(db, NULL, path);
	} else {
		*p = '\0';
		werr = create_key_recursive(db, path, p+1);
		*p = '\\';
	}

	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = regdb_create_subkey_internal(db, path, subkey);

done:
	return werr;
}

/**
 * Initialize a key in the registry:
 * create each component key of the specified path.
 */
static WERROR init_registry_key_internal(struct db_context *db,
					 const char *add_path)
{
	char *subkey, *key;
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();

	if (add_path == NULL) {
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	key = talloc_strdup(frame, add_path);

	subkey = strrchr_m(key, '\\');
	if (subkey == NULL) {
		subkey = key;
		key = NULL;
	} else {
		*subkey = '\0';
		subkey++;
	}

	werr = create_key_recursive(db, key, subkey);

done:
	talloc_free(frame);
	return werr;
}

struct init_registry_key_context {
	const char *add_path;
};

static NTSTATUS init_registry_key_action(struct db_context *db,
					 void *private_data)
{
	struct init_registry_key_context *init_ctx =
		(struct init_registry_key_context *)private_data;

	return werror_to_ntstatus(init_registry_key_internal(
					db, init_ctx->add_path));
}

/**
 * Initialize a key in the registry:
 * create each component key of the specified path,
 * wrapped in one db transaction.
 */
WERROR init_registry_key(const char *add_path)
{
	struct init_registry_key_context init_ctx;

	if (regdb_key_exists(regdb, add_path)) {
		return WERR_OK;
	}

	init_ctx.add_path = add_path;

	return regdb_trans_do(regdb,
			      init_registry_key_action,
			      &init_ctx);
}

/***********************************************************************
 Open the registry data in the tdb
 ***********************************************************************/

static void regdb_ctr_add_value(struct regval_ctr *ctr,
				struct builtin_regkey_value *value)
{
	switch(value->type) {
	case REG_DWORD:
		regval_ctr_addvalue(ctr, value->valuename, REG_DWORD,
				    (uint8_t *)&value->data.dw_value,
				    sizeof(uint32));
		break;

	case REG_SZ:
		regval_ctr_addvalue_sz(ctr, value->valuename,
				       value->data.string);
		break;

	default:
		DEBUG(0, ("regdb_ctr_add_value: invalid value type in "
			  "registry values [%d]\n", value->type));
	}
}

static NTSTATUS init_registry_data_action(struct db_context *db,
					  void *private_data)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct regval_ctr *values;
	int i;

	/* loop over all of the predefined paths and add each component */

	for (i=0; builtin_registry_paths[i] != NULL; i++) {
		if (regdb_key_exists(db, builtin_registry_paths[i])) {
			continue;
		}
		status = werror_to_ntstatus(init_registry_key_internal(db,
						  builtin_registry_paths[i]));
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	}

	/* loop over all of the predefined values and add each component */

	for (i=0; builtin_registry_values[i].path != NULL; i++) {
		WERROR werr;

		werr = regval_ctr_init(frame, &values);
		if (!W_ERROR_IS_OK(werr)) {
			status = werror_to_ntstatus(werr);
			goto done;
		}

		regdb_fetch_values_internal(db,
					    builtin_registry_values[i].path,
					    values);

		/* preserve existing values across restarts. Only add new ones */

		if (!regval_ctr_value_exists(values,
					builtin_registry_values[i].valuename))
		{
			regdb_ctr_add_value(values,
					    &builtin_registry_values[i]);
			status = regdb_store_values_internal(db,
					builtin_registry_values[i].path,
					values);
			if (!NT_STATUS_IS_OK(status)) {
				goto done;
			}
		}
		TALLOC_FREE(values);
	}

	status = NT_STATUS_OK;

done:

	TALLOC_FREE(frame);
	return status;
}

WERROR init_registry_data(void)
{
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();
	struct regval_ctr *values;
	int i;

	/*
	 * First, check for the existence of the needed keys and values.
	 * If all do already exist, we can save the writes.
	 */
	for (i=0; builtin_registry_paths[i] != NULL; i++) {
		if (!regdb_key_exists(regdb, builtin_registry_paths[i])) {
			goto do_init;
		}
	}

	for (i=0; builtin_registry_values[i].path != NULL; i++) {
		werr = regval_ctr_init(frame, &values);
		W_ERROR_NOT_OK_GOTO_DONE(werr);

		regdb_fetch_values_internal(regdb,
					    builtin_registry_values[i].path,
					    values);
		if (!regval_ctr_value_exists(values,
					builtin_registry_values[i].valuename))
		{
			TALLOC_FREE(values);
			goto do_init;
		}

		TALLOC_FREE(values);
	}

	werr = WERR_OK;
	goto done;

do_init:

	/*
	 * There are potentially quite a few store operations which are all
	 * indiviually wrapped in tdb transactions. Wrapping them in a single
	 * transaction gives just a single transaction_commit() to actually do
	 * its fsync()s. See tdb/common/transaction.c for info about nested
	 * transaction behaviour.
	 */

	werr = regdb_trans_do(regdb,
			      init_registry_data_action,
			      NULL);

done:
	TALLOC_FREE(frame);
	return werr;
}

static int regdb_normalize_keynames_fn(struct db_record *rec,
				       void *private_data)
{
	TALLOC_CTX *mem_ctx = talloc_tos();
	const char *keyname;
	NTSTATUS status;
	TDB_DATA key;
	TDB_DATA value;
	struct db_context *db = (struct db_context *)private_data;

	key = dbwrap_record_get_key(rec);
	if (key.dptr == NULL || key.dsize == 0) {
		return 0;
	}

	value = dbwrap_record_get_value(rec);

	if (db == NULL) {
		DEBUG(0, ("regdb_normalize_keynames_fn: ERROR: "
			  "NULL db context handed in via private_data\n"));
		return 1;
	}

	if (strncmp((const char *)key.dptr, REGDB_VERSION_KEYNAME,
	    strlen(REGDB_VERSION_KEYNAME)) == 0)
	{
		return 0;
	}

	keyname = strchr((const char *)key.dptr, '/');
	if (keyname) {
		keyname = talloc_string_sub(mem_ctx,
					    (const char *)key.dptr,
					    "/",
					    "\\");

		DEBUG(2, ("regdb_normalize_keynames_fn: Convert %s to %s\n",
			  (const char *)key.dptr,
			  keyname));

		/* Delete the original record and store the normalized key */
		status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("regdb_normalize_keynames_fn: "
				 "tdb_delete for [%s] failed!\n",
				 (const char *)key.dptr));
			return 1;
		}

		status = dbwrap_store_bystring(db, keyname, value, TDB_REPLACE);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("regdb_normalize_keynames_fn: "
				 "failed to store new record for [%s]!\n",
				 keyname));
			return 1;
		}
	}

	return 0;
}

static WERROR regdb_store_regdb_version(struct db_context *db, uint32_t version)
{
	NTSTATUS status;
	if (db == NULL) {
		return WERR_CAN_NOT_COMPLETE;
	}

	status = dbwrap_trans_store_int32_bystring(db, REGDB_VERSION_KEYNAME,
						   version);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("regdb_store_regdb_version: error storing %s = %d: %s\n",
			  REGDB_VERSION_KEYNAME, version, nt_errstr(status)));
		return ntstatus_to_werror(status);
	} else {
		DEBUG(10, ("regdb_store_regdb_version: stored %s = %d\n",
			  REGDB_VERSION_KEYNAME, version));
		return WERR_OK;
	}
}

static WERROR regdb_upgrade_v1_to_v2(struct db_context *db)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	WERROR werr;

	mem_ctx = talloc_stackframe();

	status = dbwrap_traverse(db, regdb_normalize_keynames_fn, db, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		werr = WERR_REG_IO_FAILURE;
		goto done;
	}

	werr = regdb_store_regdb_version(db, REGDB_VERSION_V2);

done:
	talloc_free(mem_ctx);
	return werr;
}

static bool tdb_data_read_uint32(TDB_DATA *buf, uint32_t *result)
{
	const size_t len = sizeof(uint32_t);
	if (buf->dsize >= len) {
		*result = IVAL(buf->dptr, 0);
		buf->dptr += len;
		buf->dsize -= len;
		return true;
	}
	return false;
}

static bool tdb_data_read_cstr(TDB_DATA *buf, char **result)
{
	const size_t len = strnlen((char*)buf->dptr, buf->dsize) + 1;
	if (buf->dsize >= len) {
		*result = (char*)buf->dptr;
		buf->dptr += len;
		buf->dsize -= len;
		return true;
	}
	return false;
}

static bool tdb_data_is_cstr(TDB_DATA d) {
	if (tdb_data_is_empty(d) || (d.dptr[d.dsize-1] != '\0')) {
		return false;
	}
	return strchr((char *)d.dptr, '\0') == (char *)&d.dptr[d.dsize-1];
}

static bool upgrade_v2_to_v3_check_subkeylist(struct db_context *db,
					      const char *key,
					      const char *subkey)
{
	static uint32_t zero = 0;
	static TDB_DATA empty_subkey_list = {
		.dptr = (unsigned char*)&zero,
		.dsize = sizeof(uint32_t),
	};
	bool success = false;
	char *path = talloc_asprintf(talloc_tos(), "%s\\%s", key, subkey);
	if (!strupper_m(path)) {
		goto done;
	}

	if (!dbwrap_exists(db, string_term_tdb_data(path))) {
		NTSTATUS status;

		DEBUG(10, ("regdb_upgrade_v2_to_v3: writing subkey list [%s]\n",
			   path));

		status = dbwrap_store_bystring(db, path, empty_subkey_list,
					       TDB_INSERT);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("regdb_upgrade_v2_to_v3: writing subkey list "
				  "[%s] failed\n", path));
			goto done;
		}
	}
	success = true;
done:
	talloc_free(path);
	return success;
}

static bool upgrade_v2_to_v3_check_parent(struct db_context *db,
					  const char *key)
{
	const char *sep = strrchr_m(key, '\\');
	if (sep != NULL) {
		char *pkey = talloc_strndup(talloc_tos(), key, sep-key);
		if (!dbwrap_exists(db, string_term_tdb_data(pkey))) {
			DEBUG(0, ("regdb_upgrade_v2_to_v3: missing subkey list "
				  "[%s]\nrun \"net registry check\"\n", pkey));
		}
		talloc_free(pkey);
	}
	return true;
}


#define IS_EQUAL(d,s) (((d).dsize == strlen(s)+1) &&	\
		       (strcmp((char*)(d).dptr, (s)) == 0))
#define STARTS_WITH(d,s) (((d).dsize > strlen(s)) &&			\
			  (strncmp((char*)(d).dptr, (s), strlen(s)) == 0))
#define SSTR(d) (int)(d).dsize , (char*)(d).dptr


static int regdb_upgrade_v2_to_v3_fn(struct db_record *rec, void *private_data)
{
	struct db_context *db = (struct db_context *)private_data;
	TDB_DATA key = dbwrap_record_get_key(rec);
	TDB_DATA val = dbwrap_record_get_value(rec);

	if (tdb_data_is_empty(key)) {
		return 0;
	}

	if (db == NULL) {
		DEBUG(0, ("regdb_upgrade_v2_to_v3_fn: ERROR: "
			  "NULL db context handed in via private_data\n"));
		return 1;
	}

	if (IS_EQUAL(key, REGDB_VERSION_KEYNAME) ||
	    STARTS_WITH(key, REG_VALUE_PREFIX) ||
	    STARTS_WITH(key, REG_SECDESC_PREFIX))
	{
		DEBUG(10, ("regdb_upgrade_v2_to_v3: skipping [%.*s]\n",
			   SSTR(key)));
		return 0;
	}

	if (STARTS_WITH(key, REG_SORTED_SUBKEYS_PREFIX)) {
		NTSTATUS status;
		/* Delete the deprecated sorted subkeys cache. */

		DEBUG(10, ("regdb_upgrade_v2_to_v3: deleting [%.*s]\n",
			   SSTR(key)));

		status = dbwrap_record_delete(rec);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("regdb_upgrade_v2_to_v3: deleting [%.*s] "
				  "failed!\n", SSTR(key)));
			return 1;
		}

		return 0;
	}

	if ( tdb_data_is_cstr(key) &&
	     hive_info((char*)key.dptr) != NULL )
	{
		/*
		 * Found a regular subkey list record.
		 * Walk the list and create the list record for those
		 * subkeys that don't already have one.
		 */
		TDB_DATA pos = val;
		char *subkey, *path = (char*)key.dptr;
		uint32_t num_items, found_items = 0;


		DEBUG(10, ("regdb_upgrade_v2_to_v3: scanning subkeylist of "
			   "[%s]\n", path));

		if (!tdb_data_read_uint32(&pos, &num_items)) {
			/* invalid or empty - skip */
			return 0;
		}

		while (tdb_data_read_cstr(&pos, &subkey)) {
			found_items++;

			if (!upgrade_v2_to_v3_check_subkeylist(db, path, subkey))
			{
				return 1;
			}

			if (!upgrade_v2_to_v3_check_parent(db, path)) {
				return 1;
			}
		}
		if (found_items != num_items) {
			DEBUG(0, ("regdb_upgrade_v2_to_v3: inconsistent subkey "
				  "list [%s]\nrun \"net registry check\"\n",
				  path));
		}
	} else {
		DEBUG(10, ("regdb_upgrade_v2_to_v3: skipping invalid [%.*s]\n"
			   "run \"net registry check\"\n", SSTR(key)));
	}

	return 0;
}

static WERROR regdb_upgrade_v2_to_v3(struct db_context *db)
{
	NTSTATUS status;
	WERROR werr;

	status = dbwrap_traverse(db, regdb_upgrade_v2_to_v3_fn, db, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		werr = WERR_REG_IO_FAILURE;
		goto done;
	}

	werr = regdb_store_regdb_version(db, REGDB_VERSION_V3);

done:
	return werr;
}

/***********************************************************************
 Open the registry database
 ***********************************************************************/

WERROR regdb_init(void)
{
	int32_t vers_id;
	WERROR werr;
	NTSTATUS status;

	if (regdb) {
		DEBUG(10, ("regdb_init: incrementing refcount (%d->%d)\n",
			   regdb_refcount, regdb_refcount+1));
		regdb_refcount++;
		return WERR_OK;
	}

	regdb = db_open(NULL, state_path("registry.tdb"), 0,
			REG_TDB_FLAGS, O_RDWR, 0600,
			DBWRAP_LOCK_ORDER_1, REG_DBWRAP_FLAGS);
	if (!regdb) {
		regdb = db_open(NULL, state_path("registry.tdb"), 0,
				REG_TDB_FLAGS, O_RDWR|O_CREAT, 0600,
				DBWRAP_LOCK_ORDER_1, REG_DBWRAP_FLAGS);
		if (!regdb) {
			werr = ntstatus_to_werror(map_nt_error_from_unix(errno));
			DEBUG(1,("regdb_init: Failed to open registry %s (%s)\n",
				state_path("registry.tdb"), strerror(errno) ));
			return werr;
		}

		werr = regdb_store_regdb_version(regdb, REGDB_CODE_VERSION);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(1, ("regdb_init: Failed to store version: %s\n",
				  win_errstr(werr)));
			return werr;
		}

		DEBUG(10,("regdb_init: Successfully created registry tdb\n"));
	}

	regdb_refcount = 1;
	DEBUG(10, ("regdb_init: registry db openend. refcount reset (%d)\n",
		   regdb_refcount));

	status = dbwrap_fetch_int32_bystring(regdb, REGDB_VERSION_KEYNAME,
					     &vers_id);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("regdb_init: registry version uninitialized "
			   "(got %d), initializing to version %d\n",
			   vers_id, REGDB_VERSION_V1));

		/*
		 * There was a regdb format version prior to version 1
		 * which did not store a INFO/version key. The format
		 * of this version was identical to version 1 except for
		 * the lack of the sorted subkey cache records.
		 * Since these are disposable, we can safely assume version
		 * 1 if no INFO/version key is found and run the db through
		 * the whole chain of upgrade. If the database was not
		 * initialized, this does not harm. If it was the unversioned
		 * version ("0"), then it do the right thing with the records.
		 */
		werr = regdb_store_regdb_version(regdb, REGDB_VERSION_V1);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}
		vers_id = REGDB_VERSION_V1;
	}

	if (vers_id == REGDB_CODE_VERSION) {
		return WERR_OK;
	}

	if (vers_id > REGDB_CODE_VERSION || vers_id == 0) {
		DEBUG(0, ("regdb_init: unknown registry version %d "
			  "(code version = %d), refusing initialization\n",
			  vers_id, REGDB_CODE_VERSION));
		return WERR_CAN_NOT_COMPLETE;
	}

	if (dbwrap_transaction_start(regdb) != 0) {
		return WERR_REG_IO_FAILURE;
	}

	if (vers_id == REGDB_VERSION_V1) {
		DEBUG(10, ("regdb_init: upgrading registry from version %d "
			   "to %d\n", REGDB_VERSION_V1, REGDB_VERSION_V2));

		werr = regdb_upgrade_v1_to_v2(regdb);
		if (!W_ERROR_IS_OK(werr)) {
			dbwrap_transaction_cancel(regdb);
			return werr;
		}

		vers_id = REGDB_VERSION_V2;
	}

	if (vers_id == REGDB_VERSION_V2) {
		DEBUG(10, ("regdb_init: upgrading registry from version %d "
			   "to %d\n", REGDB_VERSION_V2, REGDB_VERSION_V3));

		werr = regdb_upgrade_v2_to_v3(regdb);
		if (!W_ERROR_IS_OK(werr)) {
			dbwrap_transaction_cancel(regdb);
			return werr;
		}

		vers_id = REGDB_VERSION_V3;
	}

	/* future upgrade code should go here */

	if (dbwrap_transaction_commit(regdb) != 0) {
		return WERR_REG_IO_FAILURE;
	}

	return WERR_OK;
}

/***********************************************************************
 Open the registry.  Must already have been initialized by regdb_init()
 ***********************************************************************/

WERROR regdb_open( void )
{
	WERROR result = WERR_OK;

	if ( regdb ) {
		DEBUG(10, ("regdb_open: incrementing refcount (%d->%d)\n",
			   regdb_refcount, regdb_refcount+1));
		regdb_refcount++;
		return WERR_OK;
	}

	become_root();

	regdb = db_open(NULL, state_path("registry.tdb"), 0,
			REG_TDB_FLAGS, O_RDWR, 0600,
			DBWRAP_LOCK_ORDER_1, REG_DBWRAP_FLAGS);
	if ( !regdb ) {
		result = ntstatus_to_werror( map_nt_error_from_unix( errno ) );
		DEBUG(0,("regdb_open: Failed to open %s! (%s)\n",
			state_path("registry.tdb"), strerror(errno) ));
	}

	unbecome_root();

	regdb_refcount = 1;
	DEBUG(10, ("regdb_open: registry db opened. refcount reset (%d)\n",
		   regdb_refcount));

	return result;
}

/***********************************************************************
 ***********************************************************************/

int regdb_close( void )
{
	if (regdb_refcount == 0) {
		return 0;
	}

	regdb_refcount--;

	DEBUG(10, ("regdb_close: decrementing refcount (%d->%d)\n",
		   regdb_refcount+1, regdb_refcount));

	if ( regdb_refcount > 0 )
		return 0;

	SMB_ASSERT( regdb_refcount >= 0 );

	TALLOC_FREE(regdb);
	return 0;
}

WERROR regdb_transaction_start(void)
{
	return (dbwrap_transaction_start(regdb) == 0) ?
		WERR_OK : WERR_REG_IO_FAILURE;
}

WERROR regdb_transaction_commit(void)
{
	return (dbwrap_transaction_commit(regdb) == 0) ?
		WERR_OK : WERR_REG_IO_FAILURE;
}

WERROR regdb_transaction_cancel(void)
{
	return (dbwrap_transaction_cancel(regdb) == 0) ?
		WERR_OK : WERR_REG_IO_FAILURE;
}

/***********************************************************************
 return the tdb sequence number of the registry tdb.
 this is an indicator for the content of the registry
 having changed. it will change upon regdb_init, too, though.
 ***********************************************************************/
int regdb_get_seqnum(void)
{
	return dbwrap_get_seqnum(regdb);
}


static WERROR regdb_delete_key_with_prefix(struct db_context *db,
					   const char *keyname,
					   const char *prefix)
{
	char *path;
	WERROR werr = WERR_NOMEM;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (keyname == NULL) {
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	if (prefix == NULL) {
		path = discard_const_p(char, keyname);
	} else {
		path = talloc_asprintf(mem_ctx, "%s\\%s", prefix, keyname);
		if (path == NULL) {
			goto done;
		}
	}

	path = normalize_reg_path(mem_ctx, path);
	if (path == NULL) {
		goto done;
	}

	werr = ntstatus_to_werror(dbwrap_delete_bystring(db, path));

	/* treat "not found" as ok */
	if (W_ERROR_EQUAL(werr, WERR_NOT_FOUND)) {
		werr = WERR_OK;
	}

done:
	talloc_free(mem_ctx);
	return werr;
}


static WERROR regdb_delete_values(struct db_context *db, const char *keyname)
{
	return regdb_delete_key_with_prefix(db, keyname, REG_VALUE_PREFIX);
}

static WERROR regdb_delete_secdesc(struct db_context *db, const char *keyname)
{
	return regdb_delete_key_with_prefix(db, keyname, REG_SECDESC_PREFIX);
}

static WERROR regdb_delete_subkeylist(struct db_context *db, const char *keyname)
{
	return regdb_delete_key_with_prefix(db, keyname, NULL);
}


static WERROR regdb_delete_key_lists(struct db_context *db, const char *keyname)
{
	WERROR werr;

	werr = regdb_delete_values(db, keyname);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, (__location__ " Deleting %s\\%s failed: %s\n",
			  REG_VALUE_PREFIX, keyname, win_errstr(werr)));
		goto done;
	}

	werr = regdb_delete_secdesc(db, keyname);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, (__location__ " Deleting %s\\%s failed: %s\n",
			  REG_SECDESC_PREFIX, keyname, win_errstr(werr)));
		goto done;
	}

	werr = regdb_delete_subkeylist(db, keyname);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, (__location__ " Deleting %s failed: %s\n",
			  keyname, win_errstr(werr)));
		goto done;
	}

done:
	return werr;
}

/***********************************************************************
 Add subkey strings to the registry tdb under a defined key
 fmt is the same format as tdb_pack except this function only supports
 fstrings
 ***********************************************************************/

static WERROR regdb_store_keys_internal2(struct db_context *db,
					 const char *key,
					 struct regsubkey_ctr *ctr)
{
	TDB_DATA dbuf;
	uint8 *buffer = NULL;
	int i = 0;
	uint32 len, buflen;
	uint32 num_subkeys = regsubkey_ctr_numkeys(ctr);
	char *keyname = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	WERROR werr;

	if (!key) {
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	keyname = talloc_strdup(ctx, key);
	if (!keyname) {
		werr = WERR_NOMEM;
		goto done;
	}

	keyname = normalize_reg_path(ctx, keyname);
	if (!keyname) {
		werr = WERR_NOMEM;
		goto done;
	}

	/* allocate some initial memory */

	buffer = (uint8 *)SMB_MALLOC(1024);
	if (buffer == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}
	buflen = 1024;
	len = 0;

	/* store the number of subkeys */

	len += tdb_pack(buffer+len, buflen-len, "d", num_subkeys);

	/* pack all the strings */

	for (i=0; i<num_subkeys; i++) {
		size_t thistime;

		thistime = tdb_pack(buffer+len, buflen-len, "f",
				    regsubkey_ctr_specific_key(ctr, i));
		if (len+thistime > buflen) {
			size_t thistime2;
			/*
			 * tdb_pack hasn't done anything because of the short
			 * buffer, allocate extra space.
			 */
			buffer = SMB_REALLOC_ARRAY(buffer, uint8_t,
						   (len+thistime)*2);
			if(buffer == NULL) {
				DEBUG(0, ("regdb_store_keys: Failed to realloc "
					  "memory of size [%u]\n",
					  (unsigned int)(len+thistime)*2));
				werr = WERR_NOMEM;
				goto done;
			}
			buflen = (len+thistime)*2;
			thistime2 = tdb_pack(
				buffer+len, buflen-len, "f",
				regsubkey_ctr_specific_key(ctr, i));
			if (thistime2 != thistime) {
				DEBUG(0, ("tdb_pack failed\n"));
				werr = WERR_CAN_NOT_COMPLETE;
				goto done;
			}
		}
		len += thistime;
	}

	/* finally write out the data */

	dbuf.dptr = buffer;
	dbuf.dsize = len;
	werr = ntstatus_to_werror(dbwrap_store_bystring(db, keyname, dbuf,
							TDB_REPLACE));

done:
	TALLOC_FREE(ctx);
	SAFE_FREE(buffer);
	return werr;
}

/**
 * Utility function to store a new empty list of
 * subkeys of given key specified as parent and subkey name
 * (thereby creating the key).
 * If the parent keyname is NULL, then the "subkey" is
 * interpreted as a base key.
 * If the subkey list does already exist, it is not modified.
 *
 * Must be called from within a transaction.
 */
static WERROR regdb_store_subkey_list(struct db_context *db, const char *parent,
				      const char *key)
{
	WERROR werr;
	char *path = NULL;
	struct regsubkey_ctr *subkeys = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	if (parent == NULL) {
		path = talloc_strdup(frame, key);
	} else {
		path = talloc_asprintf(frame, "%s\\%s", parent, key);
	}
	if (!path) {
		werr = WERR_NOMEM;
		goto done;
	}

	werr = regsubkey_ctr_init(frame, &subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, path, subkeys);
	if (W_ERROR_IS_OK(werr)) {
		/* subkey list exists already - don't modify */
		goto done;
	}

	werr = regsubkey_ctr_reinit(subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	/* create a record with 0 subkeys */
	werr = regdb_store_keys_internal2(db, path, subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("regdb_store_keys: Failed to store new record for "
			  "key [%s]: %s\n", path, win_errstr(werr)));
		goto done;
	}

done:
	talloc_free(frame);
	return werr;
}

/***********************************************************************
 Store the new subkey record and create any child key records that
 do not currently exist
 ***********************************************************************/

struct regdb_store_keys_context {
	const char *key;
	struct regsubkey_ctr *ctr;
};

static NTSTATUS regdb_store_keys_action(struct db_context *db,
					void *private_data)
{
	struct regdb_store_keys_context *store_ctx;
	WERROR werr;
	int num_subkeys, i;
	char *path = NULL;
	struct regsubkey_ctr *old_subkeys = NULL;
	char *oldkeyname = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	store_ctx = (struct regdb_store_keys_context *)private_data;

	/*
	 * Re-fetch the old keys inside the transaction
	 */

	werr = regsubkey_ctr_init(mem_ctx, &old_subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, store_ctx->key, old_subkeys);
	if (!W_ERROR_IS_OK(werr) &&
	    !W_ERROR_EQUAL(werr, WERR_NOT_FOUND))
	{
		goto done;
	}

	/*
	 * Make the store operation as safe as possible without transactions:
	 *
	 * (1) For each subkey removed from ctr compared with old_subkeys:
	 *
	 *     (a) First delete the value db entry.
	 *
	 *     (b) Next delete the secdesc db record.
	 *
	 *     (c) Then delete the subkey list entry.
	 *
	 * (2) Now write the list of subkeys of the parent key,
	 *     deleting removed entries and adding new ones.
	 *
	 * (3) Finally create the subkey list entries for the added keys.
	 *
	 * This way if we crash half-way in between deleting the subkeys
	 * and storing the parent's list of subkeys, no old data can pop up
	 * out of the blue when re-adding keys later on.
	 */

	/* (1) delete removed keys' lists (values/secdesc/subkeys) */

	num_subkeys = regsubkey_ctr_numkeys(old_subkeys);
	for (i=0; i<num_subkeys; i++) {
		oldkeyname = regsubkey_ctr_specific_key(old_subkeys, i);

		if (regsubkey_ctr_key_exists(store_ctx->ctr, oldkeyname)) {
			/*
			 * It's still around, don't delete
			 */
			continue;
		}

		path = talloc_asprintf(mem_ctx, "%s\\%s", store_ctx->key,
				       oldkeyname);
		if (!path) {
			werr = WERR_NOMEM;
			goto done;
		}

		werr = regdb_delete_key_lists(db, path);
		W_ERROR_NOT_OK_GOTO_DONE(werr);

		TALLOC_FREE(path);
	}

	TALLOC_FREE(old_subkeys);

	/* (2) store the subkey list for the parent */

	werr = regdb_store_keys_internal2(db, store_ctx->key, store_ctx->ctr);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("regdb_store_keys: Failed to store new subkey list "
			 "for parent [%s]: %s\n", store_ctx->key,
			 win_errstr(werr)));
		goto done;
	}

	/* (3) now create records for any subkeys that don't already exist */

	num_subkeys = regsubkey_ctr_numkeys(store_ctx->ctr);

	for (i=0; i<num_subkeys; i++) {
		const char *subkey;

		subkey = regsubkey_ctr_specific_key(store_ctx->ctr, i);

		werr = regdb_store_subkey_list(db, store_ctx->key, subkey);
		W_ERROR_NOT_OK_GOTO_DONE(werr);
	}

	/*
	 * Update the seqnum in the container to possibly
	 * prevent next read from going to disk
	 */
	werr = regsubkey_ctr_set_seqnum(store_ctx->ctr, dbwrap_get_seqnum(db));

done:
	talloc_free(mem_ctx);
	return werror_to_ntstatus(werr);
}

static bool regdb_store_keys_internal(struct db_context *db, const char *key,
				      struct regsubkey_ctr *ctr)
{
	int num_subkeys, old_num_subkeys, i;
	struct regsubkey_ctr *old_subkeys = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	WERROR werr;
	bool ret = false;
	struct regdb_store_keys_context store_ctx;

	if (!regdb_key_exists(db, key)) {
		goto done;
	}

	/*
	 * fetch a list of the old subkeys so we can determine if anything has
	 * changed
	 */

	werr = regsubkey_ctr_init(ctx, &old_subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("regdb_store_keys: talloc() failure!\n"));
		goto done;
	}

	werr = regdb_fetch_keys_internal(db, key, old_subkeys);
	if (!W_ERROR_IS_OK(werr) &&
	    !W_ERROR_EQUAL(werr, WERR_NOT_FOUND))
	{
		goto done;
	}

	num_subkeys = regsubkey_ctr_numkeys(ctr);
	old_num_subkeys = regsubkey_ctr_numkeys(old_subkeys);
	if ((num_subkeys && old_num_subkeys) &&
	    (num_subkeys == old_num_subkeys)) {

		for (i = 0; i < num_subkeys; i++) {
			if (strcmp(regsubkey_ctr_specific_key(ctr, i),
				   regsubkey_ctr_specific_key(old_subkeys, i))
			    != 0)
			{
				break;
			}
		}
		if (i == num_subkeys) {
			/*
			 * Nothing changed, no point to even start a tdb
			 * transaction
			 */

			ret = true;
			goto done;
		}
	}

	TALLOC_FREE(old_subkeys);

	store_ctx.key = key;
	store_ctx.ctr = ctr;

	werr = regdb_trans_do(db,
			      regdb_store_keys_action,
			      &store_ctx);

	ret = W_ERROR_IS_OK(werr);

done:
	TALLOC_FREE(ctx);

	return ret;
}

static bool regdb_store_keys(const char *key, struct regsubkey_ctr *ctr)
{
	return regdb_store_keys_internal(regdb, key, ctr);
}

/**
 * create a subkey of a given key
 */

struct regdb_create_subkey_context {
	const char *key;
	const char *subkey;
};

static NTSTATUS regdb_create_subkey_action(struct db_context *db,
					   void *private_data)
{
	WERROR werr;
	struct regdb_create_subkey_context *create_ctx;
	struct regsubkey_ctr *subkeys;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	create_ctx = (struct regdb_create_subkey_context *)private_data;

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, create_ctx->key, subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regsubkey_ctr_addkey(subkeys, create_ctx->subkey);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_store_keys_internal2(db, create_ctx->key, subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, (__location__ " failed to store new subkey list for "
			 "parent key %s: %s\n", create_ctx->key,
			 win_errstr(werr)));
	}

	werr = regdb_store_subkey_list(db, create_ctx->key, create_ctx->subkey);

done:
	talloc_free(mem_ctx);
	return werror_to_ntstatus(werr);
}

static WERROR regdb_create_subkey_internal(struct db_context *db,
					   const char *key,
					   const char *subkey)
{
	WERROR werr;
	struct regsubkey_ctr *subkeys;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct regdb_create_subkey_context create_ctx;

	if (!regdb_key_exists(db, key)) {
		werr = WERR_NOT_FOUND;
		goto done;
	}

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, key, subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	if (regsubkey_ctr_key_exists(subkeys, subkey)) {
		char *newkey;

		newkey = talloc_asprintf(mem_ctx, "%s\\%s", key, subkey);
		if (newkey == NULL) {
			werr = WERR_NOMEM;
			goto done;
		}

		if (regdb_key_exists(db, newkey)) {
			werr = WERR_OK;
			goto done;
		}
	}

	talloc_free(subkeys);

	create_ctx.key = key;
	create_ctx.subkey = subkey;

	werr = regdb_trans_do(db,
			      regdb_create_subkey_action,
			      &create_ctx);

done:
	talloc_free(mem_ctx);
	return werr;
}

static WERROR regdb_create_subkey(const char *key, const char *subkey)
{
	return regdb_create_subkey_internal(regdb, key, subkey);
}

/**
 * create a base key
 */

struct regdb_create_basekey_context {
	const char *key;
};

static NTSTATUS regdb_create_basekey_action(struct db_context *db,
					    void *private_data)
{
	WERROR werr;
	struct regdb_create_basekey_context *create_ctx;

	create_ctx = (struct regdb_create_basekey_context *)private_data;

	werr = regdb_store_subkey_list(db, NULL, create_ctx->key);

	return werror_to_ntstatus(werr);
}

static WERROR regdb_create_basekey(struct db_context *db, const char *key)
{
	WERROR werr;
	struct regdb_create_subkey_context create_ctx;

	create_ctx.key = key;

	werr = regdb_trans_do(db,
			      regdb_create_basekey_action,
			      &create_ctx);

	return werr;
}

/**
 * create a subkey of a given key
 */

struct regdb_delete_subkey_context {
	const char *key;
	const char *subkey;
	const char *path;
	bool lazy;
};

static NTSTATUS regdb_delete_subkey_action(struct db_context *db,
					   void *private_data)
{
	WERROR werr;
	struct regdb_delete_subkey_context *delete_ctx;
	struct regsubkey_ctr *subkeys;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	delete_ctx = (struct regdb_delete_subkey_context *)private_data;

	werr = regdb_delete_key_lists(db, delete_ctx->path);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	if (delete_ctx->lazy) {
		goto done;
	}

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_fetch_keys_internal(db, delete_ctx->key, subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regsubkey_ctr_delkey(subkeys, delete_ctx->subkey);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_store_keys_internal2(db, delete_ctx->key, subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, (__location__ " failed to store new subkey_list for "
			 "parent key %s: %s\n", delete_ctx->key,
			 win_errstr(werr)));
	}

done:
	talloc_free(mem_ctx);
	return werror_to_ntstatus(werr);
}

static WERROR regdb_delete_subkey(const char *key, const char *subkey, bool lazy)
{
	WERROR werr;
	char *path;
	struct regdb_delete_subkey_context delete_ctx;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (!regdb_key_exists(regdb, key)) {
		werr = WERR_NOT_FOUND;
		goto done;
	}

	path = talloc_asprintf(mem_ctx, "%s\\%s", key, subkey);
	if (path == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}

	if (!regdb_key_exists(regdb, path)) {
		werr = WERR_OK;
		goto done;
	}

	delete_ctx.key = key;
	delete_ctx.subkey = subkey;
	delete_ctx.path = path;
	delete_ctx.lazy = lazy;

	werr = regdb_trans_do(regdb,
			      regdb_delete_subkey_action,
			      &delete_ctx);

done:
	talloc_free(mem_ctx);
	return werr;
}

static TDB_DATA regdb_fetch_key_internal(struct db_context *db,
					 TALLOC_CTX *mem_ctx, const char *key)
{
	char *path = NULL;
	TDB_DATA data;
	NTSTATUS status;

	path = normalize_reg_path(mem_ctx, key);
	if (!path) {
		return make_tdb_data(NULL, 0);
	}

	status = dbwrap_fetch_bystring(db, mem_ctx, path, &data);
	if (!NT_STATUS_IS_OK(status)) {
		data = tdb_null;
	}

	TALLOC_FREE(path);
	return data;
}


/**
 * Check for the existence of a key.
 *
 * Existence of a key is authoritatively defined by
 * the existence of the record that contains the list
 * of its subkeys.
 *
 * Return false, if the record does not match the correct
 * structure of an initial 4-byte counter and then a
 * list of the corresponding number of zero-terminated
 * strings.
 */
static bool regdb_key_exists(struct db_context *db, const char *key)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	TDB_DATA value;
	bool ret = false;
	char *path;
	uint32_t buflen;
	const char *buf;
	uint32_t num_items, i;
	int32_t len;

	if (key == NULL) {
		goto done;
	}

	path = normalize_reg_path(mem_ctx, key);
	if (path == NULL) {
		DEBUG(0, ("out of memory! (talloc failed)\n"));
		goto done;
	}

	if (*path == '\0') {
		goto done;
	}

	value = regdb_fetch_key_internal(db, mem_ctx, path);
	if (value.dptr == NULL) {
		goto done;
	}

	if (value.dsize == 0) {
		DEBUG(10, ("regdb_key_exists: subkeylist-record for key "
			  "[%s] is empty: Could be a deleted record in a "
			  "clustered (ctdb) environment?\n",
			  path));
		goto done;
	}

	len = tdb_unpack(value.dptr, value.dsize, "d", &num_items);
	if (len == (int32_t)-1) {
		DEBUG(1, ("regdb_key_exists: ERROR: subkeylist-record for key "
			  "[%s] is invalid: Could not parse initial 4-byte "
			  "counter. record data length is %u.\n",
			  path, (unsigned int)value.dsize));
		goto done;
	}

	/*
	 * Note: the tdb_unpack check above implies that len <= value.dsize
	 */
	buflen = value.dsize - len;
	buf = (const char *)value.dptr + len;

	len = 0;

	for (i = 0; i < num_items; i++) {
		if (buflen == 0) {
			break;
		}
		len = strnlen(buf, buflen) + 1;
		if (buflen < len) {
			DEBUG(1, ("regdb_key_exists: ERROR: subkeylist-record "
				  "for key [%s] is corrupt: %u items expected, "
				  "item number %u is not zero terminated.\n",
				  path, num_items, i+1));
			goto done;
		}

		buf += len;
		buflen -= len;
	}

	if (buflen > 0) {
		DEBUG(1, ("regdb_key_exists: ERROR: subkeylist-record for key "
			  "[%s] is corrupt: %u items expected and found, but "
			  "the record contains additional %u bytes\n",
			  path, num_items, buflen));
		goto done;
	}

	if (i < num_items) {
		DEBUG(1, ("regdb_key_exists: ERROR: subkeylist-record for key "
			  "[%s] is corrupt: %u items expected, but only %u "
			  "items found.\n",
			  path, num_items, i+1));
		goto done;
	}

	ret = true;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}


/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be
 released by the caller.
 ***********************************************************************/

static WERROR regdb_fetch_keys_internal(struct db_context *db, const char *key,
					struct regsubkey_ctr *ctr)
{
	WERROR werr;
	uint32_t num_items;
	uint8 *buf;
	uint32 buflen, len;
	int i;
	fstring subkeyname;
	TALLOC_CTX *frame = talloc_stackframe();
	TDB_DATA value;
	int seqnum[2], count;

	DEBUG(11,("regdb_fetch_keys: Enter key => [%s]\n", key ? key : "NULL"));

	if (!regdb_key_exists(db, key)) {
		DEBUG(10, ("key [%s] not found\n", key));
		werr = WERR_NOT_FOUND;
		goto done;
	}

	werr = regsubkey_ctr_reinit(ctr);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	count = 0;
	ZERO_STRUCT(value);
	seqnum[0] = dbwrap_get_seqnum(db);

	do {
		count++;
		TALLOC_FREE(value.dptr);
		value = regdb_fetch_key_internal(db, frame, key);
		seqnum[count % 2] = dbwrap_get_seqnum(db);

	} while (seqnum[0] != seqnum[1]);

	if (count > 1) {
		DEBUG(5, ("regdb_fetch_keys_internal: it took %d attempts to "
			  "fetch key '%s' with constant seqnum\n",
			  count, key));
	}

	werr = regsubkey_ctr_set_seqnum(ctr, seqnum[0]);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (value.dsize == 0 || value.dptr == NULL) {
		DEBUG(10, ("regdb_fetch_keys: no subkeys found for key [%s]\n",
			   key));
		goto done;
	}

	buf = value.dptr;
	buflen = value.dsize;
	len = tdb_unpack( buf, buflen, "d", &num_items);
	if (len == (uint32_t)-1) {
		werr = WERR_NOT_FOUND;
		goto done;
	}

	for (i=0; i<num_items; i++) {
		len += tdb_unpack(buf+len, buflen-len, "f", subkeyname);
		werr = regsubkey_ctr_addkey(ctr, subkeyname);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(5, ("regdb_fetch_keys: regsubkey_ctr_addkey "
				  "failed: %s\n", win_errstr(werr)));
			num_items = 0;
			goto done;
		}
	}

	DEBUG(11,("regdb_fetch_keys: Exit [%d] items\n", num_items));

done:
	TALLOC_FREE(frame);
	return werr;
}

static int regdb_fetch_keys(const char *key, struct regsubkey_ctr *ctr)
{
	WERROR werr;

	werr = regdb_fetch_keys_internal(regdb, key, ctr);
	if (!W_ERROR_IS_OK(werr)) {
		return -1;
	}

	return regsubkey_ctr_numkeys(ctr);
}

/****************************************************************************
 Unpack a list of registry values frem the TDB
 ***************************************************************************/

static int regdb_unpack_values(struct regval_ctr *values, uint8 *buf, int buflen)
{
	int 		len = 0;
	uint32		type;
	fstring valuename;
	uint32		size;
	uint8		*data_p;
	uint32 		num_values = 0;
	int 		i;

	/* loop and unpack the rest of the registry values */

	len += tdb_unpack(buf+len, buflen-len, "d", &num_values);

	for ( i=0; i<num_values; i++ ) {
		/* unpack the next regval */

		type = REG_NONE;
		size = 0;
		data_p = NULL;
		valuename[0] = '\0';
		len += tdb_unpack(buf+len, buflen-len, "fdB",
				  valuename,
				  &type,
				  &size,
				  &data_p);

		regval_ctr_addvalue(values, valuename, type,
				(uint8_t *)data_p, size);
		SAFE_FREE(data_p); /* 'B' option to tdb_unpack does a malloc() */

		DEBUG(10, ("regdb_unpack_values: value[%d]: name[%s] len[%d]\n",
			   i, valuename, size));
	}

	return len;
}

/****************************************************************************
 Pack all values in all printer keys
 ***************************************************************************/

static int regdb_pack_values(struct regval_ctr *values, uint8 *buf, int buflen)
{
	int 		len = 0;
	int 		i;
	struct regval_blob	*val;
	int		num_values;

	if ( !values )
		return 0;

	num_values = regval_ctr_numvals( values );

	/* pack the number of values first */

	len += tdb_pack( buf+len, buflen-len, "d", num_values );

	/* loop over all values */

	for ( i=0; i<num_values; i++ ) {
		val = regval_ctr_specific_value( values, i );
		len += tdb_pack(buf+len, buflen-len, "fdB",
				regval_name(val),
				regval_type(val),
				regval_size(val),
				regval_data_p(val) );
	}

	return len;
}

/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be
 released by the caller.
 ***********************************************************************/

static int regdb_fetch_values_internal(struct db_context *db, const char* key,
				       struct regval_ctr *values)
{
	char *keystr = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = 0;
	TDB_DATA value;
	WERROR werr;
	int seqnum[2], count;

	DEBUG(10,("regdb_fetch_values: Looking for values of key [%s]\n", key));

	if (!regdb_key_exists(db, key)) {
		DEBUG(10, ("regb_fetch_values: key [%s] does not exist\n",
			   key));
		ret = -1;
		goto done;
	}

	keystr = talloc_asprintf(ctx, "%s\\%s", REG_VALUE_PREFIX, key);
	if (!keystr) {
		goto done;
	}

	ZERO_STRUCT(value);
	count = 0;
	seqnum[0] = dbwrap_get_seqnum(db);

	do {
		count++;
		TALLOC_FREE(value.dptr);
		value = regdb_fetch_key_internal(db, ctx, keystr);
		seqnum[count % 2] = dbwrap_get_seqnum(db);
	} while (seqnum[0] != seqnum[1]);

	if (count > 1) {
		DEBUG(5, ("regdb_fetch_values_internal: it took %d attempts "
			  "to fetch key '%s' with constant seqnum\n",
			  count, key));
	}

	werr = regval_ctr_set_seqnum(values, seqnum[0]);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (!value.dptr) {
		/* all keys have zero values by default */
		goto done;
	}

	regdb_unpack_values(values, value.dptr, value.dsize);
	ret = regval_ctr_numvals(values);

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int regdb_fetch_values(const char* key, struct regval_ctr *values)
{
	return regdb_fetch_values_internal(regdb, key, values);
}

static NTSTATUS regdb_store_values_internal(struct db_context *db,
					    const char *key,
					    struct regval_ctr *values)
{
	TDB_DATA old_data, data;
	char *keystr = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int len;
	NTSTATUS status;
	WERROR werr;

	DEBUG(10,("regdb_store_values: Looking for values of key [%s]\n", key));

	if (!regdb_key_exists(db, key)) {
		status = NT_STATUS_NOT_FOUND;
		goto done;
	}

	if (regval_ctr_numvals(values) == 0) {
		werr = regdb_delete_values(db, key);
		if (!W_ERROR_IS_OK(werr)) {
			status = werror_to_ntstatus(werr);
			goto done;
		}

		/*
		 * update the seqnum in the cache to prevent the next read
		 * from going to disk
		 */
		werr = regval_ctr_set_seqnum(values, dbwrap_get_seqnum(db));
		status = werror_to_ntstatus(werr);
		goto done;
	}

	ZERO_STRUCT(data);

	len = regdb_pack_values(values, data.dptr, data.dsize);
	if (len <= 0) {
		DEBUG(0,("regdb_store_values: unable to pack values. len <= 0\n"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	data.dptr = talloc_array(ctx, uint8, len);
	data.dsize = len;

	len = regdb_pack_values(values, data.dptr, data.dsize);

	SMB_ASSERT( len == data.dsize );

	keystr = talloc_asprintf(ctx, "%s\\%s", REG_VALUE_PREFIX, key );
	if (!keystr) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	keystr = normalize_reg_path(ctx, keystr);
	if (!keystr) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = dbwrap_fetch_bystring(db, ctx, keystr, &old_data);

	if (NT_STATUS_IS_OK(status)
	    && (old_data.dptr != NULL)
	    && (old_data.dsize == data.dsize)
	    && (memcmp(old_data.dptr, data.dptr, data.dsize) == 0))
	{
		status = NT_STATUS_OK;
		goto done;
	}

	status = dbwrap_trans_store_bystring(db, keystr, data, TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("regdb_store_values_internal: error storing: %s\n", nt_errstr(status)));
		goto done;
	}

	/*
	 * update the seqnum in the cache to prevent the next read
	 * from going to disk
	 */
	werr = regval_ctr_set_seqnum(values, dbwrap_get_seqnum(db));
	status = werror_to_ntstatus(werr);

done:
	TALLOC_FREE(ctx);
	return status;
}

struct regdb_store_values_ctx {
	const char *key;
	struct regval_ctr *values;
};

static NTSTATUS regdb_store_values_action(struct db_context *db,
					  void *private_data)
{
	NTSTATUS status;
	struct regdb_store_values_ctx *ctx =
		(struct regdb_store_values_ctx *)private_data;

	status = regdb_store_values_internal(db, ctx->key, ctx->values);

	return status;
}

static bool regdb_store_values(const char *key, struct regval_ctr *values)
{
	WERROR werr;
	struct regdb_store_values_ctx ctx;

	ctx.key = key;
	ctx.values = values;

	werr = regdb_trans_do(regdb, regdb_store_values_action, &ctx);

	return W_ERROR_IS_OK(werr);
}

static WERROR regdb_get_secdesc(TALLOC_CTX *mem_ctx, const char *key,
				struct security_descriptor **psecdesc)
{
	char *tdbkey;
	TDB_DATA data;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	WERROR err = WERR_OK;

	DEBUG(10, ("regdb_get_secdesc: Getting secdesc of key [%s]\n", key));

	if (!regdb_key_exists(regdb, key)) {
		err = WERR_BADFILE;
		goto done;
	}

	tdbkey = talloc_asprintf(tmp_ctx, "%s\\%s", REG_SECDESC_PREFIX, key);
	if (tdbkey == NULL) {
		err = WERR_NOMEM;
		goto done;
	}

	tdbkey = normalize_reg_path(tmp_ctx, tdbkey);
	if (tdbkey == NULL) {
		err = WERR_NOMEM;
		goto done;
	}

	status = dbwrap_fetch_bystring(regdb, tmp_ctx, tdbkey, &data);
	if (!NT_STATUS_IS_OK(status)) {
		err = WERR_BADFILE;
		goto done;
	}

	status = unmarshall_sec_desc(mem_ctx, (uint8 *)data.dptr, data.dsize,
				     psecdesc);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY)) {
		err = WERR_NOMEM;
	} else if (!NT_STATUS_IS_OK(status)) {
		err = WERR_REG_CORRUPT;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return err;
}

struct regdb_set_secdesc_ctx {
	const char *key;
	struct security_descriptor *secdesc;
};

static NTSTATUS regdb_set_secdesc_action(struct db_context *db,
					 void *private_data)
{
	char *tdbkey;
	NTSTATUS status;
	TDB_DATA tdbdata;
	struct regdb_set_secdesc_ctx *ctx =
		(struct regdb_set_secdesc_ctx *)private_data;
	TALLOC_CTX *frame = talloc_stackframe();

	tdbkey = talloc_asprintf(frame, "%s\\%s", REG_SECDESC_PREFIX, ctx->key);
	if (tdbkey == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	tdbkey = normalize_reg_path(frame, tdbkey);
	if (tdbkey == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (ctx->secdesc == NULL) {
		/* assuming a delete */
		status = dbwrap_delete_bystring(db, tdbkey);
		goto done;
	}

	status = marshall_sec_desc(frame, ctx->secdesc, &tdbdata.dptr,
				   &tdbdata.dsize);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = dbwrap_store_bystring(db, tdbkey, tdbdata, 0);

done:
	TALLOC_FREE(frame);
	return status;
}

static WERROR regdb_set_secdesc(const char *key,
				struct security_descriptor *secdesc)
{
	WERROR err;
	struct regdb_set_secdesc_ctx ctx;

	if (!regdb_key_exists(regdb, key)) {
		err = WERR_BADFILE;
		goto done;
	}

	ctx.key = key;
	ctx.secdesc = secdesc;

	err = regdb_trans_do(regdb, regdb_set_secdesc_action, &ctx);

done:
	return err;
}

static bool regdb_subkeys_need_update(struct regsubkey_ctr *subkeys)
{
	return (regdb_get_seqnum() != regsubkey_ctr_get_seqnum(subkeys));
}

static bool regdb_values_need_update(struct regval_ctr *values)
{
	return (regdb_get_seqnum() != regval_ctr_get_seqnum(values));
}

/*
 * Table of function pointers for default access
 */

struct registry_ops regdb_ops = {
	.fetch_subkeys = regdb_fetch_keys,
	.fetch_values = regdb_fetch_values,
	.store_subkeys = regdb_store_keys,
	.store_values = regdb_store_values,
	.create_subkey = regdb_create_subkey,
	.delete_subkey = regdb_delete_subkey,
	.get_secdesc = regdb_get_secdesc,
	.set_secdesc = regdb_set_secdesc,
	.subkeys_need_update = regdb_subkeys_need_update,
	.values_need_update = regdb_values_need_update
};
