/*
   Unix SMB/CIFS implementation.

   module to store/fetch session keys for the schannel server

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2009
   Copyright (C) Guenther Deschner 2009

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
#include <tdb.h>
#include "../lib/util/util_tdb.h"
#include "../libcli/auth/libcli_auth.h"
#include "../libcli/auth/schannel_state.h"
#include "../librpc/gen_ndr/ndr_schannel.h"
#if _SAMBA_BUILD_ == 4
#include "tdb_wrap.h"
#endif

#define SECRETS_SCHANNEL_STATE "SECRETS/SCHANNEL"

/******************************************************************************
 Open or create the schannel session store tdb.
*******************************************************************************/

#define SCHANNEL_STORE_VERSION_1 1
#define SCHANNEL_STORE_VERSION_2 2 /* should not be used */
#define SCHANNEL_STORE_VERSION_CURRENT SCHANNEL_STORE_VERSION_1

static struct tdb_wrap *open_schannel_session_store(TALLOC_CTX *mem_ctx,
						    const char *private_dir)
{
	TDB_DATA vers;
	uint32_t ver;
	struct tdb_wrap *tdb_sc = NULL;
	char *fname = talloc_asprintf(mem_ctx, "%s/schannel_store.tdb", private_dir);

	if (!fname) {
		return NULL;
	}

	tdb_sc = tdb_wrap_open(mem_ctx, fname, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);

	if (!tdb_sc) {
		DEBUG(0,("open_schannel_session_store: Failed to open %s - %s\n",
			 fname, strerror(errno)));
		TALLOC_FREE(fname);
		return NULL;
	}

 again:
	vers = tdb_fetch_bystring(tdb_sc->tdb, "SCHANNEL_STORE_VERSION");
	if (vers.dptr == NULL) {
		/* First opener, no version. */
		SIVAL(&ver,0,SCHANNEL_STORE_VERSION_CURRENT);
		vers.dptr = (uint8_t *)&ver;
		vers.dsize = 4;
		tdb_store_bystring(tdb_sc->tdb, "SCHANNEL_STORE_VERSION", vers, TDB_REPLACE);
		vers.dptr = NULL;
	} else if (vers.dsize == 4) {
		ver = IVAL(vers.dptr,0);
		if (ver == SCHANNEL_STORE_VERSION_2) {
			DEBUG(0,("open_schannel_session_store: wrong version number %d in %s\n",
				(int)ver, fname ));
			tdb_wipe_all(tdb_sc->tdb);
			goto again;
		}
		if (ver != SCHANNEL_STORE_VERSION_CURRENT) {
			DEBUG(0,("open_schannel_session_store: wrong version number %d in %s\n",
				(int)ver, fname ));
			TALLOC_FREE(tdb_sc);
		}
	} else {
		TALLOC_FREE(tdb_sc);
		DEBUG(0,("open_schannel_session_store: wrong version number size %d in %s\n",
			(int)vers.dsize, fname ));
	}

	SAFE_FREE(vers.dptr);
	TALLOC_FREE(fname);

	return tdb_sc;
}

/********************************************************************
 ********************************************************************/

static
NTSTATUS schannel_store_session_key_tdb(struct tdb_wrap *tdb_sc,
					TALLOC_CTX *mem_ctx,
					struct smb_iconv_convenience *ic,
					struct netlogon_creds_CredentialState *creds)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	TDB_DATA value;
	int ret;
	char *keystr;
	char *name_upper;

	name_upper = strupper_talloc(mem_ctx, creds->computer_name);
	if (!name_upper) {
		return NT_STATUS_NO_MEMORY;
	}

	keystr = talloc_asprintf(mem_ctx, "%s/%s",
				 SECRETS_SCHANNEL_STATE, name_upper);
	TALLOC_FREE(name_upper);
	if (!keystr) {
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, ic, creds,
			(ndr_push_flags_fn_t)ndr_push_netlogon_creds_CredentialState);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(keystr);
		return ndr_map_error2ntstatus(ndr_err);
	}

	value.dptr = blob.data;
	value.dsize = blob.length;

	ret = tdb_store_bystring(tdb_sc->tdb, keystr, value, TDB_REPLACE);
	if (ret != TDB_SUCCESS) {
		DEBUG(0,("Unable to add %s to session key db - %s\n",
			 keystr, tdb_errorstr(tdb_sc->tdb)));
		talloc_free(keystr);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	DEBUG(3,("schannel_store_session_key_tdb: stored schannel info with key %s\n",
		keystr));

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(netlogon_creds_CredentialState, creds);
	}

	talloc_free(keystr);

	return NT_STATUS_OK;
}

/********************************************************************
 ********************************************************************/

static
NTSTATUS schannel_fetch_session_key_tdb(struct tdb_wrap *tdb_sc,
					TALLOC_CTX *mem_ctx,
					struct smb_iconv_convenience *ic,
					const char *computer_name,
					struct netlogon_creds_CredentialState **pcreds)
{
	NTSTATUS status;
	TDB_DATA value;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	struct netlogon_creds_CredentialState *creds = NULL;
	char *keystr = NULL;
	char *name_upper;

	*pcreds = NULL;

	name_upper = strupper_talloc(mem_ctx, computer_name);
	if (!name_upper) {
		return NT_STATUS_NO_MEMORY;
	}

	keystr = talloc_asprintf(mem_ctx, "%s/%s",
				 SECRETS_SCHANNEL_STATE, name_upper);
	TALLOC_FREE(name_upper);
	if (!keystr) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	value = tdb_fetch_bystring(tdb_sc->tdb, keystr);
	if (!value.dptr) {
		DEBUG(0,("schannel_fetch_session_key_tdb: Failed to find entry with key %s\n",
			keystr ));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	creds = talloc_zero(mem_ctx, struct netlogon_creds_CredentialState);
	if (!creds) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	blob = data_blob_const(value.dptr, value.dsize);

	ndr_err = ndr_pull_struct_blob(&blob, creds, ic, creds,
			(ndr_pull_flags_fn_t)ndr_pull_netlogon_creds_CredentialState);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		goto done;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(netlogon_creds_CredentialState, creds);
	}

	DEBUG(3,("schannel_fetch_session_key_tdb: restored schannel info key %s\n",
		keystr));

	status = NT_STATUS_OK;

 done:

	talloc_free(keystr);
	SAFE_FREE(value.dptr);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(creds);
		return status;
	}

	*pcreds = creds;

	return NT_STATUS_OK;
}

/******************************************************************************
 Wrapper around schannel_fetch_session_key_tdb()
 Note we must be root here.
*******************************************************************************/

NTSTATUS schannel_get_creds_state(TALLOC_CTX *mem_ctx,
				  struct smb_iconv_convenience *ic,
				  const char *db_priv_dir,
				  const char *computer_name,
				  struct netlogon_creds_CredentialState **_creds)
{
	TALLOC_CTX *tmpctx;
	struct tdb_wrap *tdb_sc;
	struct netlogon_creds_CredentialState *creds;
	NTSTATUS status;

	tmpctx = talloc_named(mem_ctx, 0, "schannel_get_creds_state");
	if (!tmpctx) {
		return NT_STATUS_NO_MEMORY;
	}

	tdb_sc = open_schannel_session_store(tmpctx, db_priv_dir);
	if (!tdb_sc) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status = schannel_fetch_session_key_tdb(tdb_sc, tmpctx, ic,
						computer_name, &creds);
	if (NT_STATUS_IS_OK(status)) {
		*_creds = talloc_steal(mem_ctx, creds);
		if (!*_creds) {
			status = NT_STATUS_NO_MEMORY;
		}
	}

	talloc_free(tmpctx);
	return status;
}

/******************************************************************************
 Wrapper around schannel_store_session_key_tdb()
 Note we must be root here.
*******************************************************************************/

NTSTATUS schannel_save_creds_state(TALLOC_CTX *mem_ctx,
				   struct smb_iconv_convenience *ic,
				   const char *db_priv_dir,
				   struct netlogon_creds_CredentialState *creds)
{
	TALLOC_CTX *tmpctx;
	struct tdb_wrap *tdb_sc;
	NTSTATUS status;

	tmpctx = talloc_named(mem_ctx, 0, "schannel_save_creds_state");
	if (!tmpctx) {
		return NT_STATUS_NO_MEMORY;
	}

	tdb_sc = open_schannel_session_store(tmpctx, db_priv_dir);
	if (!tdb_sc) {
		return NT_STATUS_ACCESS_DENIED;
	}

	status = schannel_store_session_key_tdb(tdb_sc, tmpctx, ic, creds);

	talloc_free(tmpctx);
	return status;
}

/********************************************************************
 Validate an incoming authenticator against the credentials for the
 remote machine stored in the schannel database.

 The credentials are (re)read and from the schannel database, and
 written back after the caclulations are performed.

 If the creds_out parameter is not NULL returns the credentials.
 ********************************************************************/

NTSTATUS schannel_check_creds_state(TALLOC_CTX *mem_ctx,
				    struct smb_iconv_convenience *ic,
				    const char *db_priv_dir,
				    const char *computer_name,
				    struct netr_Authenticator *received_authenticator,
				    struct netr_Authenticator *return_authenticator,
				    struct netlogon_creds_CredentialState **creds_out)
{
	TALLOC_CTX *tmpctx;
	struct tdb_wrap *tdb_sc;
	struct netlogon_creds_CredentialState *creds;
	NTSTATUS status;
	int ret;

	tmpctx = talloc_named(mem_ctx, 0, "schannel_check_creds_state");
	if (!tmpctx) {
		return NT_STATUS_NO_MEMORY;
	}

	tdb_sc = open_schannel_session_store(tmpctx, db_priv_dir);
	if (!tdb_sc) {
		status = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	ret = tdb_transaction_start(tdb_sc->tdb);
	if (ret != 0) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto done;
	}

	/* Because this is a shared structure (even across
	 * disconnects) we must update the database every time we
	 * update the structure */

	status = schannel_fetch_session_key_tdb(tdb_sc, tmpctx, ic,
						computer_name, &creds);
	if (!NT_STATUS_IS_OK(status)) {
		tdb_transaction_cancel(tdb_sc->tdb);
		goto done;
	}

	status = netlogon_creds_server_step_check(creds,
						  received_authenticator,
						  return_authenticator);
	if (!NT_STATUS_IS_OK(status)) {
		tdb_transaction_cancel(tdb_sc->tdb);
		goto done;
	}

	status = schannel_store_session_key_tdb(tdb_sc, tmpctx, ic, creds);
	if (!NT_STATUS_IS_OK(status)) {
		tdb_transaction_cancel(tdb_sc->tdb);
		goto done;
	}

	tdb_transaction_commit(tdb_sc->tdb);

	if (creds_out) {
		*creds_out = talloc_steal(mem_ctx, creds);
		if (!*creds_out) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	status = NT_STATUS_OK;

done:
	talloc_free(tmpctx);
	return status;
}

