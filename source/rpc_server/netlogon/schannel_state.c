/* 
   Unix SMB/CIFS implementation.

   module to store/fetch session keys for the schannel server

   Copyright (C) Andrew Tridgell 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/time.h"
#include "auth/auth.h"
#include "lib/ldb/include/ldb.h"
#include "db_wrap.h"

/* a reasonable amount of time to keep credentials live */
#define SCHANNEL_CREDENTIALS_EXPIRY 600

/*
  connect to the schannel ldb
*/
static struct ldb_context *schannel_db_connect(TALLOC_CTX *mem_ctx)
{
	char *path;
	struct ldb_context *ldb;

	path = smbd_tmp_path(mem_ctx, "schannel.ldb");
	if (!path) {
		return NULL;
	}
	
	ldb = ldb_wrap_connect(mem_ctx, path, 0, NULL);
	talloc_free(path);
	if (!ldb) {
		return NULL;
	}

	return ldb;
}

/*
  remember an established session key for a netr server authentication
  use a simple ldb structure
*/
NTSTATUS schannel_store_session_key(TALLOC_CTX *mem_ctx,
				    struct creds_CredentialState *creds)
{
	struct ldb_context *ldb;
	struct ldb_message *msg;
	struct ldb_val val, seed;
	char *s;
	char *f;
	char *sct;
	time_t expiry = time(NULL) + SCHANNEL_CREDENTIALS_EXPIRY;
	int ret;

	ldb = schannel_db_connect(mem_ctx);
	if (ldb == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	s = talloc_asprintf(mem_ctx, "%u", (unsigned int)expiry);

	if (s == NULL) {
		talloc_free(ldb);
		return NT_STATUS_NO_MEMORY;
	}

	f = talloc_asprintf(mem_ctx, "%u", (unsigned int)creds->negotiate_flags);

	if (f == NULL) {
		talloc_free(ldb);
		return NT_STATUS_NO_MEMORY;
	}

	sct = talloc_asprintf(mem_ctx, "%u", (unsigned int)creds->secure_channel_type);

	if (sct == NULL) {
		talloc_free(ldb);
		return NT_STATUS_NO_MEMORY;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		talloc_free(ldb);
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = talloc_asprintf(msg, "computerName=%s", creds->computer_name);
	if (msg->dn == NULL) {
		talloc_free(ldb);
		talloc_free(msg);
		return NT_STATUS_NO_MEMORY;
	}

	val.data = creds->session_key;
	val.length = sizeof(creds->session_key);

	seed.data = creds->seed.data;
	seed.length = sizeof(creds->seed.data);

	ldb_msg_add_value(ldb, msg, "sessionKey", &val);
	ldb_msg_add_value(ldb, msg, "seed", &seed);
	ldb_msg_add_string(ldb, msg, "expiry", s);
	ldb_msg_add_string(ldb, msg, "negotiateFlags", f);
	ldb_msg_add_string(ldb, msg, "secureChannelType", sct);
	ldb_msg_add_string(ldb, msg, "accountName", creds->account_name);
	ldb_msg_add_string(ldb, msg, "computerName", creds->computer_name);

	ldb_delete(ldb, msg->dn);

	ret = ldb_add(ldb, msg);

	talloc_free(s);

	if (ret != 0) {
		DEBUG(0,("Unable to add %s to session key db - %s\n", 
			 msg->dn, ldb_errstring(ldb)));
		talloc_free(ldb);
		talloc_free(msg);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	talloc_free(msg);
	talloc_free(ldb);

	return NT_STATUS_OK;
}


/*
  read back a credentials back for a computer
*/
NTSTATUS schannel_fetch_session_key(TALLOC_CTX *mem_ctx,
				    const char *computer_name, 
				    struct creds_CredentialState **creds)
{
	struct ldb_context *ldb;
	time_t expiry;
	struct ldb_message **res;
	int ret;
	const struct ldb_val *val;
	char *expr=NULL;

	*creds = talloc_zero(mem_ctx, struct creds_CredentialState);
	if (!*creds) {
		return NT_STATUS_NO_MEMORY;
	}

	ldb = schannel_db_connect(mem_ctx);
	if (ldb == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	expr = talloc_asprintf(mem_ctx, "(dn=computerName=%s)", computer_name);
	if (expr == NULL) {
		talloc_free(ldb);
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, expr, NULL, &res);
	if (ret != 1) {
		talloc_free(ldb);
		return NT_STATUS_INVALID_HANDLE;
	}

	expiry = ldb_msg_find_uint(res[0], "expiry", 0);
	if (expiry < time(NULL)) {
		DEBUG(1,("schannel: attempt to use expired session key for %s\n", computer_name));
		talloc_free(ldb);
		return NT_STATUS_INVALID_HANDLE;
	}

	val = ldb_msg_find_ldb_val(res[0], "sessionKey");
	if (val == NULL || val->length != 16) {
		talloc_free(ldb);
		return NT_STATUS_INVALID_HANDLE;
	}

	memcpy((*creds)->session_key, val->data, 16);

	val = ldb_msg_find_ldb_val(res[0], "seed");
	if (val == NULL || val->length != 8) {
		talloc_free(ldb);
		return NT_STATUS_INVALID_HANDLE;
	}

	memcpy((*creds)->seed.data, val->data, 8);

	(*creds)->negotiate_flags = ldb_msg_find_int(res[0], "negotiateFlags", 0);

	(*creds)->secure_channel_type = ldb_msg_find_int(res[0], "secureChannelType", 0);

	(*creds)->account_name = talloc_reference(*creds, ldb_msg_find_string(res[0], "accountName", NULL));

	(*creds)->computer_name = talloc_reference(*creds, ldb_msg_find_string(res[0], "computerName", NULL));

	talloc_free(ldb);

	return NT_STATUS_OK;
}
