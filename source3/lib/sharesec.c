/* 
 *  Unix SMB/Netbios implementation.
 *  SEC_DESC handling functions
 *  Copyright (C) Jeremy R. Allison            1995-2003.
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

#include "includes.h"
#include "system/filesys.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "util_tdb.h"
#include "libcli/util/ntstatus.h"

/*******************************************************************
 Create the share security tdb.
 ********************************************************************/

static struct db_context *share_db; /* used for share security descriptors */
#define SHARE_DATABASE_VERSION_V1 1
#define SHARE_DATABASE_VERSION_V2 2 /* version id in little endian. */
#define SHARE_DATABASE_VERSION_V3 3 /* canonicalized sharenames as lower case */

#define SHARE_SECURITY_DB_KEY_PREFIX_STR "SECDESC/"
/* Map generic permissions to file object specific permissions */

extern const struct generic_mapping file_generic_mapping;

static int delete_fn(struct db_record *rec, void *priv)
{
	dbwrap_record_delete(rec);
	return 0;
}

/*****************************************************
 Looking for keys of the form: SHARE_SECURITY_DB_KEY_PREFIX_STR + "non lower case str".
 If we find one re-write it into a canonical case form.
*****************************************************/

static int upgrade_v2_to_v3(struct db_record *rec, void *priv)
{
	size_t prefix_len = strlen(SHARE_SECURITY_DB_KEY_PREFIX_STR);
	const char *servicename = NULL;
	char *c_servicename = NULL;
	char *newkey = NULL;
	bool *p_upgrade_ok = (bool *)priv;
	NTSTATUS status;
	TDB_DATA key;
	TDB_DATA value;

	key = dbwrap_record_get_key(rec);

	/* Is there space for a one character sharename ? */
	if (key.dsize <= prefix_len+2) {
		return 0;
	}

	/* Does it start with the share key prefix ? */
	if (memcmp(key.dptr, SHARE_SECURITY_DB_KEY_PREFIX_STR,
			prefix_len) != 0) {
		return 0;
	}

	/* Is it a null terminated string as a key ? */
	if (key.dptr[key.dsize-1] != '\0') {
		return 0;
	}

	/* Bytes after the prefix are the sharename string. */
	servicename = (char *)&key.dptr[prefix_len];
	c_servicename = canonicalize_servicename(talloc_tos(), servicename);
	if (!c_servicename) {
		smb_panic("out of memory upgrading share security db from v2 -> v3");
	}

	if (strcmp(servicename, c_servicename) == 0) {
		/* Old and new names match. No canonicalization needed. */
		TALLOC_FREE(c_servicename);
		return 0;
	}

	/* Oops. Need to canonicalize name, delete old then store new. */
	status = dbwrap_record_delete(rec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("upgrade_v2_to_v3: Failed to delete secdesc for "
			  "%s: %s\n", (const char *)key.dptr,
			  nt_errstr(status)));
		TALLOC_FREE(c_servicename);
		*p_upgrade_ok = false;
		return -1;
	} else {
		DEBUG(10, ("upgrade_v2_to_v3: deleted secdesc for "
                          "%s\n", (const char *)key.dptr));
	}

	if (!(newkey = talloc_asprintf(talloc_tos(),
			SHARE_SECURITY_DB_KEY_PREFIX_STR "%s",
			c_servicename))) {
		smb_panic("out of memory upgrading share security db from v2 -> v3");
	}

	value = dbwrap_record_get_value(rec);
	status = dbwrap_store(share_db,
				string_term_tdb_data(newkey),
				value,
				TDB_REPLACE);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("upgrade_v2_to_v3: Failed to store secdesc for "
			  "%s: %s\n", c_servicename, nt_errstr(status)));
		TALLOC_FREE(c_servicename);
		TALLOC_FREE(newkey);
		*p_upgrade_ok = false;
		return -1;
	} else {
		DEBUG(10, ("upgrade_v2_to_v3: stored secdesc for "
                          "%s\n", newkey ));
	}

	TALLOC_FREE(newkey);
	TALLOC_FREE(c_servicename);

	return 0;
}

NTSTATUS share_info_db_init(void)
{
	const char *vstring = "INFO/version";
	int32_t vers_id = 0;
	bool upgrade_ok = true;
	NTSTATUS status;
	char *db_path;

	if (share_db != NULL) {
		return NT_STATUS_OK;
	}

	db_path = state_path(talloc_tos(), "share_info.tdb");
	if (db_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	share_db = db_open(NULL, db_path, 0,
			   TDB_DEFAULT, O_RDWR|O_CREAT, 0600,
			   DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (share_db == NULL) {
		DEBUG(0,("Failed to open share info database %s (%s)\n",
			 db_path, strerror(errno)));
		TALLOC_FREE(db_path);
		return map_nt_error_from_unix_common(errno);
	}
	TALLOC_FREE(db_path);

	status = dbwrap_fetch_int32_bystring(share_db, vstring, &vers_id);
	if (!NT_STATUS_IS_OK(status)) {
		vers_id = 0;
	}

	if (vers_id == SHARE_DATABASE_VERSION_V3) {
		return NT_STATUS_OK;
	}

	if (dbwrap_transaction_start(share_db) != 0) {
		DEBUG(0, ("transaction_start failed\n"));
		TALLOC_FREE(share_db);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	status = dbwrap_fetch_int32_bystring(share_db, vstring, &vers_id);
	if (!NT_STATUS_IS_OK(status)) {
		vers_id = 0;
	}

	if (vers_id == SHARE_DATABASE_VERSION_V3) {
		/*
		 * Race condition
		 */
		if (dbwrap_transaction_cancel(share_db)) {
			smb_panic("transaction_cancel failed");
		}
		return NT_STATUS_OK;
	}

	/* Move to at least V2. */

	/* Cope with byte-reversed older versions of the db. */
	if ((vers_id == SHARE_DATABASE_VERSION_V1) || (IREV(vers_id) == SHARE_DATABASE_VERSION_V1)) {
		/* Written on a bigendian machine with old fetch_int code. Save as le. */

		status = dbwrap_store_int32_bystring(
			share_db, vstring, SHARE_DATABASE_VERSION_V2);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("dbwrap_store_int32 failed: %s\n",
				  nt_errstr(status)));
			goto cancel;
		}
		vers_id = SHARE_DATABASE_VERSION_V2;
	}

	if (vers_id != SHARE_DATABASE_VERSION_V2) {
		status = dbwrap_traverse(share_db, delete_fn, NULL, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("traverse failed\n"));
			goto cancel;
		}
		status = dbwrap_store_int32_bystring(
			share_db, vstring, SHARE_DATABASE_VERSION_V2);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("dbwrap_store_int32 failed: %s\n",
				  nt_errstr(status)));
			goto cancel;
		}
	}

	/* Finally upgrade to version 3, with canonicalized sharenames. */

	status = dbwrap_traverse(share_db, upgrade_v2_to_v3, &upgrade_ok, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("traverse failed\n"));
		goto cancel;
	}
	if (!upgrade_ok) {
		DBG_ERR("upgrade failed.\n");
		status = NT_STATUS_INTERNAL_ERROR;
		goto cancel;
	}

	status = dbwrap_store_int32_bystring(
		share_db, vstring, SHARE_DATABASE_VERSION_V3);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dbwrap_store_int32 failed: %s\n",
			  nt_errstr(status)));
		goto cancel;
	}

	if (dbwrap_transaction_commit(share_db) != 0) {
		DEBUG(0, ("transaction_commit failed\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;

 cancel:
	if (dbwrap_transaction_cancel(share_db)) {
		smb_panic("transaction_cancel failed");
	}

	return status;
}

/*******************************************************************
 Fake up a Everyone, default access as a default.
 def_access is a GENERIC_XXX access mode.
 ********************************************************************/

struct security_descriptor *get_share_security_default( TALLOC_CTX *ctx, size_t *psize, uint32_t def_access)
{
	uint32_t sa;
	struct security_ace ace;
	struct security_acl *psa = NULL;
	struct security_descriptor *psd = NULL;
	uint32_t spec_access = def_access;

	se_map_generic(&spec_access, &file_generic_mapping);

	sa = (def_access | spec_access );
	init_sec_ace(&ace, &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, sa, 0);

	if ((psa = make_sec_acl(ctx, NT4_ACL_REVISION, 1, &ace)) != NULL) {
		psd = make_sec_desc(ctx, SECURITY_DESCRIPTOR_REVISION_1,
				    SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL,
				    psa, psize);
	}

	if (!psd) {
		DEBUG(0,("get_share_security: Failed to make SEC_DESC.\n"));
		return NULL;
	}

	return psd;
}

/*******************************************************************
 Pull a security descriptor from the share tdb.
 ********************************************************************/

struct security_descriptor *get_share_security( TALLOC_CTX *ctx, const char *servicename,
			      size_t *psize)
{
	char *key;
	struct security_descriptor *psd = NULL;
	TDB_DATA data;
	char *c_servicename = canonicalize_servicename(talloc_tos(), servicename);
	NTSTATUS status;

	if (!c_servicename) {
		return NULL;
	}

	status = share_info_db_init();
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(c_servicename);
		return NULL;
	}

	if (!(key = talloc_asprintf(ctx, SHARE_SECURITY_DB_KEY_PREFIX_STR "%s", c_servicename))) {
		TALLOC_FREE(c_servicename);
		DEBUG(0, ("talloc_asprintf failed\n"));
		return NULL;
	}

	TALLOC_FREE(c_servicename);

	status = dbwrap_fetch_bystring(share_db, talloc_tos(), key, &data);

	TALLOC_FREE(key);

	if (!NT_STATUS_IS_OK(status)) {
		return get_share_security_default(ctx, psize,
						  SEC_RIGHTS_DIR_ALL);
	}

	status = unmarshall_sec_desc(ctx, data.dptr, data.dsize, &psd);

	TALLOC_FREE(data.dptr);

	if (!NT_STATUS_IS_OK(status)) {
		return get_share_security_default(ctx, psize,
						  SEC_RIGHTS_DIR_ALL);
	}

	if (psd) {
		*psize = ndr_size_security_descriptor(psd, 0);
	} else {
		return get_share_security_default(ctx, psize,
						  SEC_RIGHTS_DIR_ALL);
	}

	return psd;
}

/*******************************************************************
 Store a security descriptor in the share db.
 ********************************************************************/

NTSTATUS set_share_security(const char *share_name,
			    struct security_descriptor *psd)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *key;
	TDB_DATA blob;
	NTSTATUS status;
	char *c_share_name = canonicalize_servicename(frame, share_name);

	if (c_share_name == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	status = share_info_db_init();
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = marshall_sec_desc(frame, psd, &blob.dptr, &blob.dsize);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("marshall_sec_desc failed: %s\n",
			  nt_errstr(status)));
		goto out;
	}

	if (!(key = talloc_asprintf(frame, SHARE_SECURITY_DB_KEY_PREFIX_STR "%s", c_share_name))) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	status = dbwrap_trans_store(share_db, string_term_tdb_data(key), blob,
				    TDB_REPLACE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("set_share_security: Failed to store secdesc for "
			  "%s: %s\n", share_name, nt_errstr(status)));
		goto out;
	}

	DEBUG(5,("set_share_security: stored secdesc for %s\n", share_name ));
	status = NT_STATUS_OK;

 out:
	TALLOC_FREE(frame);
	return status;
}

/*******************************************************************
 Delete a security descriptor.
********************************************************************/

NTSTATUS delete_share_security(const char *servicename)
{
	TDB_DATA kbuf;
	char *key;
	NTSTATUS status;
	char *c_servicename = canonicalize_servicename(talloc_tos(), servicename);

	if (c_servicename == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = share_info_db_init();
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(c_servicename);
		return status;
	}

	if (!(key = talloc_asprintf(talloc_tos(), SHARE_SECURITY_DB_KEY_PREFIX_STR "%s",
				    c_servicename))) {
		TALLOC_FREE(c_servicename);
		return NT_STATUS_NO_MEMORY;
	}
	kbuf = string_term_tdb_data(key);

	status = dbwrap_trans_delete(share_db, kbuf);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("delete_share_security: Failed to delete entry for "
			  "share %s: %s\n", c_servicename, nt_errstr(status)));
		TALLOC_FREE(c_servicename);
		return status;
	}

	TALLOC_FREE(c_servicename);
	return NT_STATUS_OK;
}

/*******************************************************************
 Can this user access with share with the required permissions ?
********************************************************************/

bool share_access_check(const struct security_token *token,
			const char *sharename,
			uint32_t desired_access,
			uint32_t *pgranted)
{
	uint32_t granted;
	NTSTATUS status;
	struct security_descriptor *psd = NULL;
	size_t sd_size;

	psd = get_share_security(talloc_tos(), sharename, &sd_size);

	if (!psd) {
		if (pgranted != NULL) {
			*pgranted = desired_access;
		}
		return false;
	}

	status = se_file_access_check(psd, token, true, desired_access, &granted);

	TALLOC_FREE(psd);

	if (pgranted != NULL) {
		*pgranted = granted;
	}

	return NT_STATUS_IS_OK(status);
}

/***************************************************************************
 Parse the contents of an acl string from a usershare file.
***************************************************************************/

bool parse_usershare_acl(TALLOC_CTX *ctx, const char *acl_str, struct security_descriptor **ppsd)
{
	size_t s_size = 0;
	const char *pacl = acl_str;
	int num_aces = 0;
	struct security_ace *ace_list = NULL;
	struct security_acl *psa = NULL;
	struct security_descriptor *psd = NULL;
	size_t sd_size = 0;
	int i;

	*ppsd = NULL;

	/* If the acl string is blank return "Everyone:R" */
	if (!*acl_str) {
		struct security_descriptor *default_psd = get_share_security_default(ctx, &s_size, GENERIC_READ_ACCESS);
		if (!default_psd) {
			return False;
		}
		*ppsd = default_psd;
		return True;
	}

	num_aces = 1;

	/* Add the number of ',' characters to get the number of aces. */
	num_aces += count_chars(pacl,',');

	ace_list = talloc_array(ctx, struct security_ace, num_aces);
	if (!ace_list) {
		return False;
	}

	for (i = 0; i < num_aces; i++) {
		uint32_t sa;
		uint32_t g_access;
		uint32_t s_access;
		struct dom_sid sid;
		char *sidstr;
		enum security_ace_type type = SEC_ACE_TYPE_ACCESS_ALLOWED;

		if (!next_token_talloc(ctx, &pacl, &sidstr, ":")) {
			DEBUG(0,("parse_usershare_acl: malformed usershare acl looking "
				"for ':' in string '%s'\n", pacl));
			return False;
		}

		if (!string_to_sid(&sid, sidstr)) {
			DEBUG(0,("parse_usershare_acl: failed to convert %s to sid.\n",
				sidstr ));
			return False;
		}

		switch (*pacl) {
			case 'F': /* Full Control, ie. R+W */
			case 'f': /* Full Control, ie. R+W */
				s_access = g_access = GENERIC_ALL_ACCESS;
				break;
			case 'R': /* Read only. */
			case 'r': /* Read only. */
				s_access = g_access = GENERIC_READ_ACCESS;
				break;
			case 'D': /* Deny all to this SID. */
			case 'd': /* Deny all to this SID. */
				type = SEC_ACE_TYPE_ACCESS_DENIED;
				s_access = g_access = GENERIC_ALL_ACCESS;
				break;
			default:
				DEBUG(0,("parse_usershare_acl: unknown acl type at %s.\n",
					pacl ));
				return False;
		}

		pacl++;
		if (*pacl && *pacl != ',') {
			DEBUG(0,("parse_usershare_acl: bad acl string at %s.\n",
				pacl ));
			return False;
		}
		pacl++; /* Go past any ',' */

		se_map_generic(&s_access, &file_generic_mapping);
		sa = (g_access | s_access);
		init_sec_ace(&ace_list[i], &sid, type, sa, 0);
	}

	if ((psa = make_sec_acl(ctx, NT4_ACL_REVISION, num_aces, ace_list)) != NULL) {
		psd = make_sec_desc(ctx, SECURITY_DESCRIPTOR_REVISION_1,
				    SEC_DESC_SELF_RELATIVE, NULL, NULL, NULL,
				    psa, &sd_size);
	}

	if (!psd) {
		DEBUG(0,("parse_usershare_acl: Failed to make SEC_DESC.\n"));
		return False;
	}

	*ppsd = psd;
	return True;
}
