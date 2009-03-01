/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter                     2002-2005
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

static struct db_context *regdb = NULL;
static int regdb_refcount;

static bool regdb_key_exists(const char *key);
static bool regdb_key_is_base_key(const char *key);

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
	KEY_WINLOGON_GPEXT_PATH,
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

/**
 * Initialize a key in the registry:
 * create each component key of the specified path.
 */
static WERROR init_registry_key_internal(const char *add_path)
{
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();
	char *path = NULL;
	char *base = NULL;
	char *remaining = NULL;
	char *keyname;
	char *subkeyname;
	struct regsubkey_ctr *subkeys;
	const char *p, *p2;

	DEBUG(6, ("init_registry_key: Adding [%s]\n", add_path));

	path = talloc_strdup(frame, add_path);
	base = talloc_strdup(frame, "");
	if (!path || !base) {
		werr = WERR_NOMEM;
		goto fail;
	}
	p = path;

	while (next_token_talloc(frame, &p, &keyname, "\\")) {

		/* build up the registry path from the components */

		if (*base) {
			base = talloc_asprintf(frame, "%s\\", base);
			if (!base) {
				werr = WERR_NOMEM;
				goto fail;
			}
		}
		base = talloc_asprintf_append(base, "%s", keyname);
		if (!base) {
			werr = WERR_NOMEM;
			goto fail;
		}

		/* get the immediate subkeyname (if we have one ) */

		subkeyname = talloc_strdup(frame, "");
		if (!subkeyname) {
			werr = WERR_NOMEM;
			goto fail;
		}
		if (*p) {
			remaining = talloc_strdup(frame, p);
			if (!remaining) {
				werr = WERR_NOMEM;
				goto fail;
			}
			p2 = remaining;

			if (!next_token_talloc(frame, &p2,
						&subkeyname, "\\"))
			{
				subkeyname = talloc_strdup(frame,p2);
				if (!subkeyname) {
					werr = WERR_NOMEM;
					goto fail;
				}
			}
		}

		DEBUG(10,("init_registry_key: Storing key [%s] with "
			  "subkey [%s]\n", base,
			  *subkeyname ? subkeyname : "NULL"));

		/* we don't really care if the lookup succeeds or not
		 * since we are about to update the record.
		 * We just want any subkeys already present */

		werr = regsubkey_ctr_init(frame, &subkeys);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,("talloc() failure!\n"));
			goto fail;
		}

		regdb_fetch_keys(base, subkeys);
		if (*subkeyname) {
			werr = regsubkey_ctr_addkey(subkeys, subkeyname);
			if (!W_ERROR_IS_OK(werr)) {
				goto fail;
			}
		}
		if (!regdb_store_keys( base, subkeys)) {
			werr = WERR_CAN_NOT_COMPLETE;
			goto fail;
		}
	}

	werr = WERR_OK;

fail:
	TALLOC_FREE(frame);
	return werr;
}

/**
 * Initialize a key in the registry:
 * create each component key of the specified path,
 * wrapped in one db transaction.
 */
WERROR init_registry_key(const char *add_path)
{
	WERROR werr;

	if (regdb_key_exists(add_path)) {
		return WERR_OK;
	}

	if (regdb->transaction_start(regdb) != 0) {
		DEBUG(0, ("init_registry_key: transaction_start failed\n"));
		return WERR_REG_IO_FAILURE;
	}

	werr = init_registry_key_internal(add_path);
	if (!W_ERROR_IS_OK(werr)) {
		goto fail;
	}

	if (regdb->transaction_commit(regdb) != 0) {
		DEBUG(0, ("init_registry_key: Could not commit transaction\n"));
		return WERR_REG_IO_FAILURE;
	}

	return WERR_OK;

fail:
	if (regdb->transaction_cancel(regdb) != 0) {
		smb_panic("init_registry_key: transaction_cancel failed\n");
	}

	return werr;
}

/***********************************************************************
 Open the registry data in the tdb
 ***********************************************************************/

WERROR init_registry_data(void)
{
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();
	REGVAL_CTR *values;
	int i;
	UNISTR2 data;

	/*
	 * First, check for the existence of the needed keys and values.
	 * If all do already exist, we can save the writes.
	 */
	for (i=0; builtin_registry_paths[i] != NULL; i++) {
		if (!regdb_key_exists(builtin_registry_paths[i])) {
			goto do_init;
		}
	}

	for (i=0; builtin_registry_values[i].path != NULL; i++) {
		values = TALLOC_ZERO_P(frame, REGVAL_CTR);
		if (values == NULL) {
			werr = WERR_NOMEM;
			goto done;
		}

		regdb_fetch_values(builtin_registry_values[i].path, values);
		if (!regval_ctr_key_exists(values,
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

	if (regdb->transaction_start(regdb) != 0) {
		DEBUG(0, ("init_registry_data: tdb_transaction_start "
			  "failed\n"));
		werr = WERR_REG_IO_FAILURE;
		goto done;
	}

	/* loop over all of the predefined paths and add each component */

	for (i=0; builtin_registry_paths[i] != NULL; i++) {
		if (regdb_key_exists(builtin_registry_paths[i])) {
			continue;
		}
		werr = init_registry_key_internal(builtin_registry_paths[i]);
		if (!W_ERROR_IS_OK(werr)) {
			goto fail;
		}
	}

	/* loop over all of the predefined values and add each component */

	for (i=0; builtin_registry_values[i].path != NULL; i++) {

		values = TALLOC_ZERO_P(frame, REGVAL_CTR);
		if (values == NULL) {
			werr = WERR_NOMEM;
			goto fail;
		}

		regdb_fetch_values(builtin_registry_values[i].path, values);

		/* preserve existing values across restarts. Only add new ones */

		if (!regval_ctr_key_exists(values,
					builtin_registry_values[i].valuename))
		{
			switch(builtin_registry_values[i].type) {
			case REG_DWORD:
				regval_ctr_addvalue(values,
					builtin_registry_values[i].valuename,
					REG_DWORD,
					(char*)&builtin_registry_values[i].data.dw_value,
					sizeof(uint32));
				break;

			case REG_SZ:
				init_unistr2(&data,
					builtin_registry_values[i].data.string,
					UNI_STR_TERMINATE);
				regval_ctr_addvalue(values,
					builtin_registry_values[i].valuename,
					REG_SZ,
					(char*)data.buffer,
					data.uni_str_len*sizeof(uint16));
				break;

			default:
				DEBUG(0, ("init_registry_data: invalid value "
					  "type in builtin_registry_values "
					  "[%d]\n",
					  builtin_registry_values[i].type));
			}
			regdb_store_values(builtin_registry_values[i].path,
					   values);
		}
		TALLOC_FREE(values);
	}

	if (regdb->transaction_commit(regdb) != 0) {
		DEBUG(0, ("init_registry_data: Could not commit "
			  "transaction\n"));
		werr = WERR_REG_IO_FAILURE;
	} else {
		werr = WERR_OK;
	}

	goto done;

fail:
	if (regdb->transaction_cancel(regdb) != 0) {
		smb_panic("init_registry_data: tdb_transaction_cancel "
			  "failed\n");
	}

done:
	TALLOC_FREE(frame);
	return werr;
}

/***********************************************************************
 Open the registry database
 ***********************************************************************/
 
WERROR regdb_init(void)
{
	const char *vstring = "INFO/version";
	uint32 vers_id;
	WERROR werr;

	if (regdb) {
		DEBUG(10, ("regdb_init: incrementing refcount (%d)\n",
			  regdb_refcount));
		regdb_refcount++;
		return WERR_OK;
	}

	regdb = db_open(NULL, state_path("registry.tdb"), 0,
			      REG_TDB_FLAGS, O_RDWR, 0600);
	if (!regdb) {
		regdb = db_open(NULL, state_path("registry.tdb"), 0,
				      REG_TDB_FLAGS, O_RDWR|O_CREAT, 0600);
		if (!regdb) {
			werr = ntstatus_to_werror(map_nt_error_from_unix(errno));
			DEBUG(1,("regdb_init: Failed to open registry %s (%s)\n",
				state_path("registry.tdb"), strerror(errno) ));
			return werr;
		}
		
		DEBUG(10,("regdb_init: Successfully created registry tdb\n"));
	}

	regdb_refcount = 1;

	vers_id = dbwrap_fetch_int32(regdb, vstring);

	if ( vers_id != REGVER_V1 ) {
		NTSTATUS status;
		/* any upgrade code here if needed */
		DEBUG(10, ("regdb_init: got %s = %d != %d\n", vstring,
			   vers_id, REGVER_V1));
		status = dbwrap_trans_store_int32(regdb, vstring, REGVER_V1);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("regdb_init: error storing %s = %d: %s\n",
				  vstring, REGVER_V1, nt_errstr(status)));
			return ntstatus_to_werror(status);
		} else {
			DEBUG(10, ("regdb_init: stored %s = %d\n",
				  vstring, REGVER_V1));
		}
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
		DEBUG(10,("regdb_open: incrementing refcount (%d)\n", regdb_refcount));
		regdb_refcount++;
		return WERR_OK;
	}
	
	become_root();

	regdb = db_open(NULL, state_path("registry.tdb"), 0,
			      REG_TDB_FLAGS, O_RDWR, 0600);
	if ( !regdb ) {
		result = ntstatus_to_werror( map_nt_error_from_unix( errno ) );
		DEBUG(0,("regdb_open: Failed to open %s! (%s)\n", 
			state_path("registry.tdb"), strerror(errno) ));
	}

	unbecome_root();

	regdb_refcount = 1;
	DEBUG(10,("regdb_open: refcount reset (%d)\n", regdb_refcount));

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

	DEBUG(10,("regdb_close: decrementing refcount (%d)\n", regdb_refcount));

	if ( regdb_refcount > 0 )
		return 0;

	SMB_ASSERT( regdb_refcount >= 0 );

	TALLOC_FREE(regdb);
	return 0;
}

WERROR regdb_transaction_start(void)
{
	return (regdb->transaction_start(regdb) == 0) ?
		WERR_OK : WERR_REG_IO_FAILURE;
}

WERROR regdb_transaction_commit(void)
{
	return (regdb->transaction_commit(regdb) == 0) ?
		WERR_OK : WERR_REG_IO_FAILURE;
}

WERROR regdb_transaction_cancel(void)
{
	return (regdb->transaction_cancel(regdb) == 0) ?
		WERR_OK : WERR_REG_IO_FAILURE;
}

/***********************************************************************
 return the tdb sequence number of the registry tdb.
 this is an indicator for the content of the registry
 having changed. it will change upon regdb_init, too, though.
 ***********************************************************************/
int regdb_get_seqnum(void)
{
	return regdb->get_seqnum(regdb);
}


static WERROR regdb_delete_key_with_prefix(const char *keyname,
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
		path = talloc_asprintf(mem_ctx, "%s/%s", prefix, keyname);
		if (path == NULL) {
			goto done;
		}
	}

	path = normalize_reg_path(mem_ctx, path);
	if (path == NULL) {
		goto done;
	}

	werr = ntstatus_to_werror(dbwrap_delete_bystring(regdb, path));

	/* treat "not" found" as ok */
	if (W_ERROR_EQUAL(werr, WERR_NOT_FOUND)) {
		werr = WERR_OK;
	}

done:
	talloc_free(mem_ctx);
	return werr;
}


static WERROR regdb_delete_values(const char *keyname)
{
	return regdb_delete_key_with_prefix(keyname, REG_VALUE_PREFIX);
}

static WERROR regdb_delete_secdesc(const char *keyname)
{
	return regdb_delete_key_with_prefix(keyname, REG_SECDESC_PREFIX);
}

static WERROR regdb_delete_subkeylist(const char *keyname)
{
	return regdb_delete_key_with_prefix(keyname, NULL);
}

static WERROR regdb_delete_key_lists(const char *keyname)
{
	WERROR werr;

	werr = regdb_delete_values(keyname);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, (__location__ " Deleting %s/%s failed: %s\n",
			  REG_VALUE_PREFIX, keyname, win_errstr(werr)));
		goto done;
	}

	werr = regdb_delete_secdesc(keyname);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, (__location__ " Deleting %s/%s failed: %s\n",
			  REG_SECDESC_PREFIX, keyname, win_errstr(werr)));
		goto done;
	}

	werr = regdb_delete_subkeylist(keyname);
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

static bool regdb_store_keys_internal(const char *key, struct regsubkey_ctr *ctr)
{
	TDB_DATA dbuf;
	uint8 *buffer = NULL;
	int i = 0;
	uint32 len, buflen;
	bool ret = true;
	uint32 num_subkeys = regsubkey_ctr_numkeys(ctr);
	char *keyname = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	NTSTATUS status;

	if (!key) {
		return false;
	}

	keyname = talloc_strdup(ctx, key);
	if (!keyname) {
		return false;
	}
	keyname = normalize_reg_path(ctx, keyname);

	/* allocate some initial memory */

	buffer = (uint8 *)SMB_MALLOC(1024);
	if (buffer == NULL) {
		return false;
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
				ret = false;
				goto done;
			}
			buflen = (len+thistime)*2;
			thistime2 = tdb_pack(
				buffer+len, buflen-len, "f",
				regsubkey_ctr_specific_key(ctr, i));
			if (thistime2 != thistime) {
				DEBUG(0, ("tdb_pack failed\n"));
				ret = false;
				goto done;
			}
		}
		len += thistime;
	}

	/* finally write out the data */

	dbuf.dptr = buffer;
	dbuf.dsize = len;
	status = dbwrap_store_bystring(regdb, keyname, dbuf, TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
		goto done;
	}

	/*
	 * Delete a sorted subkey cache for regdb_key_exists, will be
	 * recreated automatically
	 */
	keyname = talloc_asprintf(ctx, "%s/%s", REG_SORTED_SUBKEYS_PREFIX,
				  keyname);
	if (keyname != NULL) {
		dbwrap_delete_bystring(regdb, keyname);
	}

done:
	TALLOC_FREE(ctx);
	SAFE_FREE(buffer);
	return ret;
}

/***********************************************************************
 Store the new subkey record and create any child key records that
 do not currently exist
 ***********************************************************************/

bool regdb_store_keys(const char *key, struct regsubkey_ctr *ctr)
{
	int num_subkeys, old_num_subkeys, i;
	char *path = NULL;
	struct regsubkey_ctr *subkeys = NULL, *old_subkeys = NULL;
	char *oldkeyname = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	WERROR werr;

	if (!regdb_key_is_base_key(key) && !regdb_key_exists(key)) {
		goto fail;
	}

	/*
	 * fetch a list of the old subkeys so we can determine if anything has
	 * changed
	 */

	werr = regsubkey_ctr_init(ctx, &old_subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("regdb_store_keys: talloc() failure!\n"));
		return false;
	}

	regdb_fetch_keys(key, old_subkeys);

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
			TALLOC_FREE(old_subkeys);
			return true;
		}
	}

	TALLOC_FREE(old_subkeys);

	if (regdb->transaction_start(regdb) != 0) {
		DEBUG(0, ("regdb_store_keys: transaction_start failed\n"));
		goto fail;
	}

	/*
	 * Re-fetch the old keys inside the transaction
	 */

	werr = regsubkey_ctr_init(ctx, &old_subkeys);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("regdb_store_keys: talloc() failure!\n"));
		goto cancel;
	}

	regdb_fetch_keys(key, old_subkeys);

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

		if (regsubkey_ctr_key_exists(ctr, oldkeyname)) {
			/*
			 * It's still around, don't delete
			 */

			continue;
		}

		path = talloc_asprintf(ctx, "%s/%s", key, oldkeyname);
		if (!path) {
			goto cancel;
		}

		werr = regdb_delete_key_lists(path);
		W_ERROR_NOT_OK_GOTO(werr, cancel);

		TALLOC_FREE(path);
	}

	TALLOC_FREE(old_subkeys);

	/* (2) store the subkey list for the parent */

	if (!regdb_store_keys_internal(key, ctr) ) {
		DEBUG(0,("regdb_store_keys: Failed to store new subkey list "
			 "for parent [%s]\n", key));
		goto cancel;
	}

	/* (3) now create records for any subkeys that don't already exist */

	num_subkeys = regsubkey_ctr_numkeys(ctr);

	if (num_subkeys == 0) {
		werr = regsubkey_ctr_init(ctx, &subkeys);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,("regdb_store_keys: talloc() failure!\n"));
			goto cancel;
		}

		if (!regdb_store_keys_internal(key, subkeys)) {
			DEBUG(0,("regdb_store_keys: Failed to store "
				 "new record for key [%s]\n", key));
			goto cancel;
		}
		TALLOC_FREE(subkeys);

	}

	for (i=0; i<num_subkeys; i++) {
		path = talloc_asprintf(ctx, "%s/%s",
					key,
					regsubkey_ctr_specific_key(ctr, i));
		if (!path) {
			goto cancel;
		}
		werr = regsubkey_ctr_init(ctx, &subkeys);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,("regdb_store_keys: talloc() failure!\n"));
			goto cancel;
		}

		if (regdb_fetch_keys( path, subkeys ) == -1) {
			/* create a record with 0 subkeys */
			if (!regdb_store_keys_internal(path, subkeys)) {
				DEBUG(0,("regdb_store_keys: Failed to store "
					 "new record for key [%s]\n", path));
				goto cancel;
			}
		}

		TALLOC_FREE(subkeys);
		TALLOC_FREE(path);
	}

	if (regdb->transaction_commit(regdb) != 0) {
		DEBUG(0, ("regdb_store_keys: Could not commit transaction\n"));
		goto fail;
	}

	TALLOC_FREE(ctx);
	return true;

cancel:
	if (regdb->transaction_cancel(regdb) != 0) {
		smb_panic("regdb_store_keys: transaction_cancel failed\n");
	}

fail:
	TALLOC_FREE(ctx);

	return false;
}

static WERROR regdb_create_subkey(const char *key, const char *subkey)
{
	WERROR werr;
	struct regsubkey_ctr *subkeys;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (!regdb_key_is_base_key(key) && !regdb_key_exists(key)) {
		werr = WERR_NOT_FOUND;
		goto done;
	}

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	if (regdb_fetch_keys(key, subkeys) < 0) {
		werr = WERR_REG_IO_FAILURE;
		goto done;
	}

	if (regsubkey_ctr_key_exists(subkeys, subkey)) {
		werr = WERR_OK;
		goto done;
	}

	talloc_free(subkeys);

	werr = regdb_transaction_start();
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	W_ERROR_NOT_OK_GOTO(werr, cancel);

	if (regdb_fetch_keys(key, subkeys) < 0) {
		werr = WERR_REG_IO_FAILURE;
		goto cancel;
	}

	werr = regsubkey_ctr_addkey(subkeys, subkey);
	W_ERROR_NOT_OK_GOTO(werr, cancel);

	if (!regdb_store_keys_internal(key, subkeys)) {
		DEBUG(0, (__location__ " failed to store new subkey list for "
			 "parent key %s\n", key));
		werr = WERR_REG_IO_FAILURE;
		goto cancel;
	}

	werr = regdb_transaction_commit();
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, (__location__ " failed to commit transaction: %s\n",
			 win_errstr(werr)));
	}

	goto done;

cancel:
	werr = regdb_transaction_cancel();
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, (__location__ " failed to cancel transaction: %s\n",
			 win_errstr(werr)));
	}

done:
	talloc_free(mem_ctx);
	return werr;
}

static WERROR regdb_delete_subkey(const char *key, const char *subkey)
{
	WERROR werr, werr2;
	struct regsubkey_ctr *subkeys;
	char *path;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (!regdb_key_is_base_key(key) && !regdb_key_exists(key)) {
		werr = WERR_NOT_FOUND;
		goto done;
	}

	path = talloc_asprintf(mem_ctx, "%s/%s", key, subkey);
	if (path == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}

	if (!regdb_key_exists(path)) {
		werr = WERR_OK;
		goto done;
	}

	werr = regdb_transaction_start();
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	werr = regdb_delete_key_lists(path);
	W_ERROR_NOT_OK_GOTO(werr, cancel);

	werr = regsubkey_ctr_init(mem_ctx, &subkeys);
	W_ERROR_NOT_OK_GOTO(werr, cancel);

	if (regdb_fetch_keys(key, subkeys) < 0) {
		werr = WERR_REG_IO_FAILURE;
		goto cancel;
	}

	werr = regsubkey_ctr_delkey(subkeys, subkey);
	W_ERROR_NOT_OK_GOTO(werr, cancel);

	if (!regdb_store_keys_internal(key, subkeys)) {
		DEBUG(0, (__location__ " failed to store new subkey_list for "
			 "parent key %s\n", key));
		werr = WERR_REG_IO_FAILURE;
		goto cancel;
	}

	werr = regdb_transaction_commit();
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, (__location__ " failed to commit transaction: %s\n",
			 win_errstr(werr)));
	}

	goto done;

cancel:
	werr2 = regdb_transaction_cancel();
	if (!W_ERROR_IS_OK(werr2)) {
		DEBUG(0, (__location__ " failed to cancel transaction: %s\n",
			 win_errstr(werr2)));
	}

done:
	talloc_free(mem_ctx);
	return werr;
}

static TDB_DATA regdb_fetch_key_internal(TALLOC_CTX *mem_ctx, const char *key)
{
	char *path = NULL;
	TDB_DATA data;

	path = normalize_reg_path(mem_ctx, key);
	if (!path) {
		return make_tdb_data(NULL, 0);
	}

	data = dbwrap_fetch_bystring(regdb, mem_ctx, path);

	TALLOC_FREE(path);
	return data;
}


/**
 * check whether a given key name represents a base key,
 * i.e one without a subkey separator ('/' or '\').
 */
static bool regdb_key_is_base_key(const char *key)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	bool ret = false;
	char *path;

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

	ret = (strrchr(path, '/') == NULL);

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/*
 * regdb_key_exists() is a very frequent operation. It can be quite
 * time-consuming to fully fetch the parent's subkey list, talloc_strdup all
 * subkeys and then compare the keyname linearly to all the parent's subkeys.
 *
 * The following code tries to make this operation as efficient as possible:
 * Per registry key we create a list of subkeys that is very efficient to
 * search for existence of a subkey. Its format is:
 *
 * 4 bytes num_subkeys
 * 4*num_subkey bytes offset into the string array
 * then follows a sorted list of subkeys in uppercase
 *
 * This record is created by create_sorted_subkeys() on demand if it does not
 * exist. scan_parent_subkeys() uses regdb->parse_record to search the sorted
 * list, the parsing code and the binary search can be found in
 * parent_subkey_scanner. The code uses parse_record() to avoid a memcpy of
 * the potentially large subkey record.
 *
 * The sorted subkey record is deleted in regdb_store_keys_internal and
 * recreated on demand.
 */

static int cmp_keynames(const void *p1, const void *p2)
{
	return StrCaseCmp(*((char **)p1), *((char **)p2));
}

static bool create_sorted_subkeys(const char *key, const char *sorted_keyname)
{
	char **sorted_subkeys;
	struct regsubkey_ctr *ctr;
	bool result = false;
	NTSTATUS status;
	char *buf;
	char *p;
	int i, res;
	size_t len;
	int num_subkeys;
	WERROR werr;

	if (regdb->transaction_start(regdb) != 0) {
		DEBUG(0, ("create_sorted_subkeys: transaction_start "
			  "failed\n"));
		return false;
	}

	werr = regsubkey_ctr_init(talloc_tos(), &ctr);
	if (!W_ERROR_IS_OK(werr)) {
		goto fail;
	}

	res = regdb_fetch_keys(key, ctr);
	if (res == -1) {
		goto fail;
	}

	num_subkeys = regsubkey_ctr_numkeys(ctr);
	sorted_subkeys = talloc_array(ctr, char *, num_subkeys);
	if (sorted_subkeys == NULL) {
		goto fail;
	}

	len = 4 + 4*num_subkeys;

	for (i = 0; i < num_subkeys; i++) {
		sorted_subkeys[i] = talloc_strdup_upper(sorted_subkeys,
					regsubkey_ctr_specific_key(ctr, i));
		if (sorted_subkeys[i] == NULL) {
			goto fail;
		}
		len += strlen(sorted_subkeys[i])+1;
	}

	qsort(sorted_subkeys, num_subkeys, sizeof(char *), cmp_keynames);

	buf = talloc_array(ctr, char, len);
	if (buf == NULL) {
		goto fail;
	}
	p = buf + 4 + 4*num_subkeys;

	SIVAL(buf, 0, num_subkeys);

	for (i=0; i < num_subkeys; i++) {
		ptrdiff_t offset = p - buf;
		SIVAL(buf, 4 + 4*i, offset);
		strlcpy(p, sorted_subkeys[i], len-offset);
		p += strlen(sorted_subkeys[i]) + 1;
	}

	status = dbwrap_store_bystring(
		regdb, sorted_keyname, make_tdb_data((uint8_t *)buf, len),
		TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * Don't use a "goto fail;" here, this would commit the broken
		 * transaction. See below for an explanation.
		 */
		if (regdb->transaction_cancel(regdb) == -1) {
			DEBUG(0, ("create_sorted_subkeys: transaction_cancel "
				  "failed\n"));
		}
		TALLOC_FREE(ctr);
		return false;
	}

	result = true;
 fail:
	/*
	 * We only get here via the "goto fail" when we did not write anything
	 * yet. Using transaction_commit even in a failure case is necessary
	 * because this (disposable) call might be nested in other
	 * transactions. Doing a cancel here would destroy the possibility of
	 * a transaction_commit for transactions that we might be wrapped in.
	 */
	if (regdb->transaction_commit(regdb) == -1) {
		DEBUG(0, ("create_sorted_subkeys: transaction_start "
			  "failed\n"));
		goto fail;
	}

	TALLOC_FREE(ctr);
	return result;
}

struct scan_subkey_state {
	char *name;
	bool scanned;
	bool found;
};

static int parent_subkey_scanner(TDB_DATA key, TDB_DATA data,
				 void *private_data)
{
	struct scan_subkey_state *state =
		(struct scan_subkey_state *)private_data;
	uint32_t num_subkeys;
	uint32_t l, u;

	if (data.dsize < sizeof(uint32_t)) {
		return -1;
	}

	state->scanned = true;
	state->found = false;

	tdb_unpack(data.dptr, data.dsize, "d", &num_subkeys);

	l = 0;
	u = num_subkeys;

	while (l < u) {
		uint32_t idx = (l+u)/2;
		char *s = (char *)data.dptr + IVAL(data.dptr, 4 + 4*idx);
		int comparison = strcmp(state->name, s);

		if (comparison < 0) {
			u = idx;
		} else if (comparison > 0) {
			l = idx + 1;
		} else {
			state->found = true;
			return 0;
		}
	}
	return 0;
}

static bool scan_parent_subkeys(const char *parent, const char *name)
{
	char *path = NULL;
	char *key = NULL;
	struct scan_subkey_state state = { 0, };
	bool result = false;
	int res;

	state.name = NULL;

	path = normalize_reg_path(talloc_tos(), parent);
	if (path == NULL) {
		goto fail;
	}

	key = talloc_asprintf(talloc_tos(), "%s/%s",
			      REG_SORTED_SUBKEYS_PREFIX, path);
	if (key == NULL) {
		goto fail;
	}

	state.name = talloc_strdup_upper(talloc_tos(), name);
	if (state.name == NULL) {
		goto fail;
	}
	state.scanned = false;

	res = regdb->parse_record(regdb, string_term_tdb_data(key),
				  parent_subkey_scanner, &state);

	if (state.scanned) {
		result = state.found;
	} else {
		if (!create_sorted_subkeys(path, key)) {
			goto fail;
		}
		res = regdb->parse_record(regdb, string_term_tdb_data(key),
					  parent_subkey_scanner, &state);
		if ((res == 0) && (state.scanned)) {
			result = state.found;
		}
	}

 fail:
	TALLOC_FREE(path);
	TALLOC_FREE(state.name);
	return result;
}

/**
 * Check for the existence of a key.
 *
 * Existence of a key is authoritatively defined by its
 * existence in the list of subkeys of its parent key.
 * The exeption of this are keys without a parent key,
 * i.e. the "base" keys (HKLM, HKCU, ...).
 */
static bool regdb_key_exists(const char *key)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	TDB_DATA value;
	bool ret = false;
	char *path, *p;

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

	p = strrchr(path, '/');
	if (p == NULL) {
		/* this is a base key */
		value = regdb_fetch_key_internal(mem_ctx, path);
		ret = (value.dptr != NULL);
	} else {
		*p = '\0';
		ret = scan_parent_subkeys(path, p+1);
	}

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}


/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be
 released by the caller.
 ***********************************************************************/

int regdb_fetch_keys(const char *key, struct regsubkey_ctr *ctr)
{
	WERROR werr;
	uint32 num_items;
	uint8 *buf;
	uint32 buflen, len;
	int i;
	fstring subkeyname;
	int ret = -1;
	TALLOC_CTX *frame = talloc_stackframe();
	TDB_DATA value;

	DEBUG(11,("regdb_fetch_keys: Enter key => [%s]\n", key ? key : "NULL"));

	if (!regdb_key_exists(key)) {
		goto done;
	}

	werr = regsubkey_ctr_set_seqnum(ctr, regdb_get_seqnum());
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	value = regdb_fetch_key_internal(frame, key);

	if (value.dptr == NULL) {
		DEBUG(10, ("regdb_fetch_keys: no subkeys found for key [%s]\n",
			   key));
		ret = 0;
		goto done;
	}

	buf = value.dptr;
	buflen = value.dsize;
	len = tdb_unpack( buf, buflen, "d", &num_items);

	for (i=0; i<num_items; i++) {
		len += tdb_unpack(buf+len, buflen-len, "f", subkeyname);
		werr = regsubkey_ctr_addkey(ctr, subkeyname);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(5, ("regdb_fetch_keys: regsubkey_ctr_addkey "
				  "failed: %s\n", win_errstr(werr)));
			goto done;
		}
	}

	DEBUG(11,("regdb_fetch_keys: Exit [%d] items\n", num_items));

	ret = num_items;
done:
	TALLOC_FREE(frame);
	return ret;
}

/****************************************************************************
 Unpack a list of registry values frem the TDB
 ***************************************************************************/

static int regdb_unpack_values(REGVAL_CTR *values, uint8 *buf, int buflen)
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

		/* add the new value. Paranoid protective code -- make sure data_p is valid */

		if (*valuename && size && data_p) {
			regval_ctr_addvalue(values, valuename, type,
					(const char *)data_p, size);
		}
		SAFE_FREE(data_p); /* 'B' option to tdb_unpack does a malloc() */

		DEBUG(8,("specific: [%s], len: %d\n", valuename, size));
	}

	return len;
}

/****************************************************************************
 Pack all values in all printer keys
 ***************************************************************************/

static int regdb_pack_values(REGVAL_CTR *values, uint8 *buf, int buflen)
{
	int 		len = 0;
	int 		i;
	REGISTRY_VALUE	*val;
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

int regdb_fetch_values( const char* key, REGVAL_CTR *values )
{
	char *keystr = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = 0;
	TDB_DATA value;

	DEBUG(10,("regdb_fetch_values: Looking for value of key [%s] \n", key));

	if (!regdb_key_exists(key)) {
		goto done;
	}

	keystr = talloc_asprintf(ctx, "%s/%s", REG_VALUE_PREFIX, key);
	if (!keystr) {
		goto done;
	}

	values->seqnum = regdb_get_seqnum();

	value = regdb_fetch_key_internal(ctx, keystr);

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

bool regdb_store_values( const char *key, REGVAL_CTR *values )
{
	TDB_DATA old_data, data;
	char *keystr = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int len;
	NTSTATUS status;
	bool result = false;

	DEBUG(10,("regdb_store_values: Looking for value of key [%s] \n", key));

	if (!regdb_key_exists(key)) {
		goto done;
	}

	ZERO_STRUCT(data);

	len = regdb_pack_values(values, data.dptr, data.dsize);
	if (len <= 0) {
		DEBUG(0,("regdb_store_values: unable to pack values. len <= 0\n"));
		goto done;
	}

	data.dptr = TALLOC_ARRAY(ctx, uint8, len);
	data.dsize = len;

	len = regdb_pack_values(values, data.dptr, data.dsize);

	SMB_ASSERT( len == data.dsize );

	keystr = talloc_asprintf(ctx, "%s/%s", REG_VALUE_PREFIX, key );
	if (!keystr) {
		goto done;
	}
	keystr = normalize_reg_path(ctx, keystr);
	if (!keystr) {
		goto done;
	}

	old_data = dbwrap_fetch_bystring(regdb, ctx, keystr);

	if ((old_data.dptr != NULL)
	    && (old_data.dsize == data.dsize)
	    && (memcmp(old_data.dptr, data.dptr, data.dsize) == 0))
	{
		result = true;
		goto done;
	}

	status = dbwrap_trans_store_bystring(regdb, keystr, data, TDB_REPLACE);

	result = NT_STATUS_IS_OK(status);

done:
	TALLOC_FREE(ctx);
	return result;
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

	if (!regdb_key_exists(key)) {
		err = WERR_BADFILE;
		goto done;
	}

	tdbkey = talloc_asprintf(tmp_ctx, "%s/%s", REG_SECDESC_PREFIX, key);
	if (tdbkey == NULL) {
		err = WERR_NOMEM;
		goto done;
	}
	normalize_dbkey(tdbkey);

	data = dbwrap_fetch_bystring(regdb, tmp_ctx, tdbkey);
	if (data.dptr == NULL) {
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

static WERROR regdb_set_secdesc(const char *key,
				struct security_descriptor *secdesc)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	char *tdbkey;
	WERROR err = WERR_NOMEM;
	TDB_DATA tdbdata;

	if (!regdb_key_exists(key)) {
		err = WERR_BADFILE;
		goto done;
	}

	tdbkey = talloc_asprintf(mem_ctx, "%s/%s", REG_SECDESC_PREFIX, key);
	if (tdbkey == NULL) {
		goto done;
	}
	normalize_dbkey(tdbkey);

	if (secdesc == NULL) {
		/* assuming a delete */
		err = ntstatus_to_werror(dbwrap_trans_delete_bystring(regdb,
								      tdbkey));
		goto done;
	}

	err = ntstatus_to_werror(marshall_sec_desc(mem_ctx, secdesc,
						   &tdbdata.dptr,
						   &tdbdata.dsize));
	W_ERROR_NOT_OK_GOTO_DONE(err);

	err = ntstatus_to_werror(dbwrap_trans_store_bystring(regdb, tdbkey,
							     tdbdata, 0));

 done:
	TALLOC_FREE(mem_ctx);
	return err;
}

bool regdb_subkeys_need_update(struct regsubkey_ctr *subkeys)
{
	return (regdb_get_seqnum() != regsubkey_ctr_get_seqnum(subkeys));
}

bool regdb_values_need_update(REGVAL_CTR *values)
{
	return (regdb_get_seqnum() != values->seqnum);
}

/* 
 * Table of function pointers for default access
 */
 
REGISTRY_OPS regdb_ops = {
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
