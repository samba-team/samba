/*
   Unix SMB/CIFS implementation.
   msDS-ManagedPassword attribute for Group Managed Service Accounts

   Copyright (C) Catalyst.Net Ltd 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef DSDB_GMSA_UTIL_H
#define DSDB_GMSA_UTIL_H

#include "ldb.h"
#include "ldb_module.h"
#include <talloc.h>

#include "lib/crypto/gkdi.h"
#include "lib/crypto/gmsa.h"
#include "lib/util/data_blob.h"
#include "lib/util/time.h"

struct gmsa_update {
	/* The DN of the gMSA to be updated. */
	struct ldb_dn *dn;
	/*
	 * The managed password ID (if any) found in the database at the time of
	 * preparing this update.
	 */
	const DATA_BLOB *found_pwd_id;
	/* An optional request to set the previous password. */
	struct ldb_request *old_pw_req;
	/* A request to set the current password. */
	struct ldb_request *new_pw_req;
	/* An request to set the managed password ID. */
	struct ldb_request *pwd_id_req;
};

struct gmsa_update_pwd_part {
	const struct ProvRootKey *root_key;
	struct Gkid gkid;
};

struct gmsa_update_pwd {
	struct gmsa_update_pwd_part prev_id;
	struct gmsa_update_pwd_part new_id;
};

struct dom_sid;
int gmsa_allowed_to_view_managed_password(TALLOC_CTX *mem_ctx,
					  struct ldb_context *ldb,
					  const struct ldb_message *msg,
					  const struct dom_sid *account_sid,
					  bool *allowed_out);

struct KeyEnvelope;
void gmsa_update_managed_pwd_id(struct KeyEnvelope *pwd_id,
				const struct gmsa_update_pwd_part *new_pwd);

NTSTATUS gmsa_pack_managed_pwd_id(TALLOC_CTX *mem_ctx,
				  const struct KeyEnvelope *pwd_id,
				  DATA_BLOB *pwd_id_out);

int gmsa_generate_blobs(struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			const NTTIME current_time,
			const struct dom_sid *const account_sid,
			DATA_BLOB *pwd_id_blob_out,
			struct gmsa_null_terminated_password **password_out);

NTSTATUS gmsa_pack_managed_pwd(TALLOC_CTX *mem_ctx,
			       const uint8_t *new_password,
			       const uint8_t *old_password,
			       uint64_t query_interval,
			       uint64_t unchanged_interval,
			       DATA_BLOB *managed_pwd_out);

bool dsdb_account_is_gmsa(struct ldb_context *ldb,
			  const struct ldb_message *msg);

const struct KeyEnvelopeId *gmsa_get_managed_pwd_id(
	const struct ldb_message *msg,
	struct KeyEnvelopeId *key_env_out);

struct gmsa_return_pwd {
	struct gmsa_null_terminated_password *prev_pwd;
	struct gmsa_null_terminated_password *new_pwd;
	NTTIME query_interval;
	NTTIME unchanged_interval;
};

bool samdb_gmsa_key_is_recent(const struct ldb_message *msg,
			      const NTTIME current_time);

/*
 * Recalculate the managed password of an account. The account referred to by
 * ‘msg’ should be a Group Managed Service Account.
 *
 * Updated passwords are returned in ‘update_out’.
 *
 * Pass in a non‐NULL pointer for ‘return_out’ if you want the passwords as
 * reflected by the msDS-ManagedPassword operational attribute.
 */
int gmsa_recalculate_managed_pwd(TALLOC_CTX *mem_ctx,
				 struct ldb_context *ldb,
				 const struct ldb_message *msg,
				 const NTTIME current_time,
				 struct gmsa_update **update_out,
				 struct gmsa_return_pwd *return_out);

int dsdb_update_gmsa_entry_keys(TALLOC_CTX *mem_ctx,
				struct ldb_context *ldb,
				const struct gmsa_update *gmsa_update);

int dsdb_update_gmsa_keys(TALLOC_CTX *mem_ctx,
			  struct ldb_context *ldb,
			  const struct ldb_result *res,
			  bool *retry_out);

#define DSDB_GMSA_TIME_OPAQUE ("dsdb_gmsa_time_opaque")

bool dsdb_gmsa_current_time(struct ldb_context *ldb, NTTIME *current_time_out);

#endif /* DSDB_GMSA_UTIL_H */
