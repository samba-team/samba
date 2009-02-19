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
	REGSUBKEY_CTR *subkeys;
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

		if (!(subkeys = TALLOC_ZERO_P(frame, REGSUBKEY_CTR))) {
			DEBUG(0,("talloc() failure!\n"));
			werr = WERR_NOMEM;
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
	TALLOC_CTX *frame = NULL;
	REGVAL_CTR *values;
	int i;
	UNISTR2 data;

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
		return WERR_REG_IO_FAILURE;
	}

	/* loop over all of the predefined paths and add each component */

	for (i=0; builtin_registry_paths[i] != NULL; i++) {
		werr = init_registry_key_internal(builtin_registry_paths[i]);
		if (!W_ERROR_IS_OK(werr)) {
			goto fail;
		}
	}

	/* loop over all of the predefined values and add each component */

	frame = talloc_stackframe();

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

	TALLOC_FREE(frame);

	if (regdb->transaction_commit(regdb) != 0) {
		DEBUG(0, ("init_registry_data: Could not commit "
			  "transaction\n"));
		return WERR_REG_IO_FAILURE;
	}

	return WERR_OK;

 fail:

	TALLOC_FREE(frame);

	if (regdb->transaction_cancel(regdb) != 0) {
		smb_panic("init_registry_data: tdb_transaction_cancel "
			  "failed\n");
	}

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

	regdb = db_open_trans(NULL, state_path("registry.tdb"), 0,
			      REG_TDB_FLAGS, O_RDWR, 0600);
	if (!regdb) {
		regdb = db_open_trans(NULL, state_path("registry.tdb"), 0,
				      REG_TDB_FLAGS, O_RDWR|O_CREAT, 0600);
		if (!regdb) {
			werr = ntstatus_to_werror(map_nt_error_from_unix(errno));
			DEBUG(0,("regdb_init: Failed to open registry %s (%s)\n",
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
			DEBUG(0, ("regdb_init: error storing %s = %d: %s\n",
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

	regdb = db_open_trans(NULL, state_path("registry.tdb"), 0,
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

/***********************************************************************
 return the tdb sequence number of the registry tdb.
 this is an indicator for the content of the registry
 having changed. it will change upon regdb_init, too, though.
 ***********************************************************************/
int regdb_get_seqnum(void)
{
	return regdb->get_seqnum(regdb);
}

/***********************************************************************
 Add subkey strings to the registry tdb under a defined key
 fmt is the same format as tdb_pack except this function only supports
 fstrings
 ***********************************************************************/

static bool regdb_store_keys_internal(const char *key, REGSUBKEY_CTR *ctr)
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
					  "memory of size [%d]\n",
					  (len+thistime)*2));
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

done:
	TALLOC_FREE(ctx);
	SAFE_FREE(buffer);
	return ret;
}

/***********************************************************************
 Store the new subkey record and create any child key records that
 do not currently exist
 ***********************************************************************/

bool regdb_store_keys(const char *key, REGSUBKEY_CTR *ctr)
{
	int num_subkeys, i;
	char *path = NULL;
	REGSUBKEY_CTR *subkeys = NULL, *old_subkeys = NULL;
	char *oldkeyname = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	NTSTATUS status;

	/*
	 * fetch a list of the old subkeys so we can determine if anything has
	 * changed
	 */

	if (!(old_subkeys = TALLOC_ZERO_P(ctx, REGSUBKEY_CTR))) {
		DEBUG(0,("regdb_store_keys: talloc() failure!\n"));
		return false;
	}

	regdb_fetch_keys(key, old_subkeys);

	if ((ctr->num_subkeys && old_subkeys->num_subkeys) &&
	    (ctr->num_subkeys == old_subkeys->num_subkeys)) {

		for (i = 0; i<ctr->num_subkeys; i++) {
			if (strcmp(ctr->subkeys[i],
				   old_subkeys->subkeys[i]) != 0) {
				break;
			}
		}
		if (i == ctr->num_subkeys) {
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

	if (!(old_subkeys = TALLOC_ZERO_P(ctx, REGSUBKEY_CTR))) {
		DEBUG(0,("regdb_store_keys: talloc() failure!\n"));
		goto cancel;
	}

	regdb_fetch_keys(key, old_subkeys);

	/* store the subkey list for the parent */

	if (!regdb_store_keys_internal(key, ctr) ) {
		DEBUG(0,("regdb_store_keys: Failed to store new subkey list "
			 "for parent [%s]\n", key));
		goto cancel;
	}

	/* now delete removed keys */

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
		path = normalize_reg_path(ctx, path);
		if (!path) {
			goto cancel;
		}
		status = dbwrap_delete_bystring(regdb, path);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Deleting %s failed\n", path));
			goto cancel;
		}

		TALLOC_FREE(path);
		path = talloc_asprintf(ctx, "%s/%s/%s",
				REG_VALUE_PREFIX,
				key,
				oldkeyname );
		if (!path) {
			goto cancel;
		}
		path = normalize_reg_path(ctx, path);
		if (!path) {
			goto cancel;
		}

		/*
		 * Ignore errors here, we might have no values around
		 */
		dbwrap_delete_bystring(regdb, path);
		TALLOC_FREE(path);
	}

	TALLOC_FREE(old_subkeys);

	/* now create records for any subkeys that don't already exist */

	num_subkeys = regsubkey_ctr_numkeys(ctr);

	if (num_subkeys == 0) {
		if (!(subkeys = TALLOC_ZERO_P(ctx, REGSUBKEY_CTR)) ) {
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
		if (!(subkeys = TALLOC_ZERO_P(ctx, REGSUBKEY_CTR)) ) {
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


/***********************************************************************
 Retrieve an array of strings containing subkeys.  Memory should be
 released by the caller.
 ***********************************************************************/

int regdb_fetch_keys(const char *key, REGSUBKEY_CTR *ctr)
{
	char *path = NULL;
	uint32 num_items;
	uint8 *buf;
	uint32 buflen, len;
	int i;
	fstring subkeyname;
	int ret = -1;
	int dbret = -1;
	TALLOC_CTX *frame = talloc_stackframe();
	TDB_DATA value;

	DEBUG(11,("regdb_fetch_keys: Enter key => [%s]\n", key ? key : "NULL"));

	path = talloc_strdup(frame, key);
	if (!path) {
		goto fail;
	}

	/* convert to key format */
	path = talloc_string_sub(frame, path, "\\", "/");
	if (!path) {
		goto fail;
	}
	strupper_m(path);

	ctr->seqnum = regdb_get_seqnum();

	dbret = regdb->fetch(regdb, frame, string_term_tdb_data(path), &value);
	if (dbret != 0) {
		goto fail;
	}

	buf = value.dptr;
	buflen = value.dsize;

	if ( !buf ) {
		DEBUG(5,("regdb_fetch_keys: tdb lookup failed to locate key [%s]\n", key));
		goto fail;
	}

	len = tdb_unpack( buf, buflen, "d", &num_items);

	/*
	 * The following code breaks the abstraction that reg_objects.c sets
	 * up with regsubkey_ctr_addkey(). But if we use that with the current
	 * data structure of ctr->subkeys being an unsorted array, we end up
	 * with an O(n^2) algorithm for retrieving keys from the tdb
	 * file. This is pretty pointless, as we have to trust the data
	 * structure on disk not to have duplicates anyway. The alternative to
	 * breaking this abstraction would be to set up a more sophisticated
	 * data structure in REGSUBKEY_CTR.
	 *
	 * This makes "net conf list" for a registry with >1000 shares
	 * actually usable :-)
	 */

	ctr->subkeys = talloc_array(ctr, char *, num_items);
	if (ctr->subkeys == NULL) {
		DEBUG(5, ("regdb_fetch_keys: could not allocate subkeys\n"));
		goto fail;
	}
	ctr->num_subkeys = num_items;

	for (i=0; i<num_items; i++) {
		len += tdb_unpack(buf+len, buflen-len, "f", subkeyname);
		ctr->subkeys[i] = talloc_strdup(ctr->subkeys, subkeyname);
		if (ctr->subkeys[i] == NULL) {
			DEBUG(5, ("regdb_fetch_keys: could not allocate "
				  "subkeyname\n"));
			TALLOC_FREE(ctr->subkeys);
			ctr->num_subkeys = 0;
			goto fail;
		}
	}

	DEBUG(11,("regdb_fetch_keys: Exit [%d] items\n", num_items));

	ret = num_items;
 fail:
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
	int dbret = -1;
	TDB_DATA value;

	DEBUG(10,("regdb_fetch_values: Looking for value of key [%s] \n", key));

	keystr = talloc_asprintf(ctx, "%s/%s", REG_VALUE_PREFIX, key);
	if (!keystr) {
		return 0;
	}
	keystr = normalize_reg_path(ctx, keystr);
	if (!keystr) {
		goto done;
	}

	values->seqnum = regdb_get_seqnum();

	dbret = regdb->fetch(regdb, ctx, string_term_tdb_data(keystr), &value);
	if (dbret != 0) {
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

bool regdb_store_values( const char *key, REGVAL_CTR *values )
{
	TDB_DATA old_data, data;
	char *keystr = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int len;
	NTSTATUS status;
	bool result = false;

	DEBUG(10,("regdb_store_values: Looking for value of key [%s] \n", key));

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

	status = dbwrap_trans_store(regdb, string_term_tdb_data(keystr), data,
				    TDB_REPLACE);

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
	NTSTATUS status;
	WERROR err = WERR_NOMEM;
	TDB_DATA tdbdata;

	tdbkey = talloc_asprintf(mem_ctx, "%s/%s", REG_SECDESC_PREFIX, key);
	if (tdbkey == NULL) {
		goto done;
	}
	normalize_dbkey(tdbkey);

	if (secdesc == NULL) {
		/* assuming a delete */
		status = dbwrap_trans_delete(regdb,
					     string_term_tdb_data(tdbkey));
		if (NT_STATUS_IS_OK(status)) {
			err = WERR_OK;
		} else {
			err = ntstatus_to_werror(status);
		}
		goto done;
	}

	err = ntstatus_to_werror(marshall_sec_desc(mem_ctx, secdesc,
						   &tdbdata.dptr,
						   &tdbdata.dsize));
	if (!W_ERROR_IS_OK(err)) {
		goto done;
	}

	status = dbwrap_trans_store(regdb, string_term_tdb_data(tdbkey),
				    tdbdata, 0);
	if (!NT_STATUS_IS_OK(status)) {
		err = ntstatus_to_werror(status);
		goto done;
	}

 done:
	TALLOC_FREE(mem_ctx);
	return err;
}

bool regdb_subkeys_need_update(REGSUBKEY_CTR *subkeys)
{
	return (regdb_get_seqnum() != subkeys->seqnum);
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
	.get_secdesc = regdb_get_secdesc,
	.set_secdesc = regdb_set_secdesc,
	.subkeys_need_update = regdb_subkeys_need_update,
	.values_need_update = regdb_values_need_update
};
