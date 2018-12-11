/*
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Andrew Bartlett      2002
   Copyright (C) Rafal Szczesniak     2002
   Copyright (C) Tim Potter           2001

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

/* the Samba secrets database stores any generated, private information
   such as the local SID and machine trust password */

#include "includes.h"
#include "passdb.h"
#include "passdb/pdb_secrets.h"
#include "librpc/gen_ndr/ndr_secrets.h"
#include "secrets.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/security.h"
#include "util_tdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

/**
 * Get trusted domains info from secrets.tdb.
 **/

struct list_trusted_domains_state {
	uint32_t num_domains;
	struct trustdom_info **domains;
};

static int list_trusted_domain(struct db_record *rec, void *private_data)
{
	const size_t prefix_len = strlen(SECRETS_DOMTRUST_ACCT_PASS);
	struct TRUSTED_DOM_PASS pass;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	struct trustdom_info *dom_info;
	TDB_DATA key;
	TDB_DATA value;

	struct list_trusted_domains_state *state =
		(struct list_trusted_domains_state *)private_data;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	if ((key.dsize < prefix_len)
	    || (strncmp((char *)key.dptr, SECRETS_DOMTRUST_ACCT_PASS,
			prefix_len) != 0)) {
		return 0;
	}

	blob = data_blob_const(value.dptr, value.dsize);

	ndr_err = ndr_pull_struct_blob(&blob, talloc_tos(), &pass,
			(ndr_pull_flags_fn_t)ndr_pull_TRUSTED_DOM_PASS);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	if (pass.domain_sid.num_auths != 4) {
		struct dom_sid_buf buf;
		DEBUG(0, ("SID %s is not a domain sid, has %d "
			  "auths instead of 4\n",
			  dom_sid_str_buf(&pass.domain_sid, &buf),
			  pass.domain_sid.num_auths));
		return 0;
	}

	if (!(dom_info = talloc(state->domains, struct trustdom_info))) {
		DEBUG(0, ("talloc failed\n"));
		return 0;
	}

	dom_info->name = talloc_strdup(dom_info, pass.uni_name);
	if (!dom_info->name) {
		TALLOC_FREE(dom_info);
		return 0;
	}

	sid_copy(&dom_info->sid, &pass.domain_sid);

	ADD_TO_ARRAY(state->domains, struct trustdom_info *, dom_info,
		     &state->domains, &state->num_domains);

	if (state->domains == NULL) {
		state->num_domains = 0;
		return -1;
	}
	return 0;
}

NTSTATUS secrets_trusted_domains(TALLOC_CTX *mem_ctx, uint32_t *num_domains,
				 struct trustdom_info ***domains)
{
	struct list_trusted_domains_state state;
	struct db_context *db_ctx;

	if (!secrets_init()) {
		return NT_STATUS_ACCESS_DENIED;
	}

	db_ctx = secrets_db_ctx();

	state.num_domains = 0;

	/*
	 * Make sure that a talloc context for the trustdom_info structs
	 * exists
	 */

	if (!(state.domains = talloc_array(
		      mem_ctx, struct trustdom_info *, 1))) {
		return NT_STATUS_NO_MEMORY;
	}

	dbwrap_traverse_read(db_ctx, list_trusted_domain, (void *)&state, NULL);

	*num_domains = state.num_domains;
	*domains = state.domains;
	return NT_STATUS_OK;
}

/* In order to avoid direct linking against libsecrets for pdb modules
 * following helpers are provided for pdb module writers.
 * To differentiate them from pdb_* API, they are prefixed by PDB upper case
 */
bool PDB_secrets_store_domain_sid(const char *domain, const struct dom_sid *sid)
{
	return secrets_store_domain_sid(domain, sid);
}

bool PDB_secrets_mark_domain_protected(const char *domain)
{
	return secrets_mark_domain_protected(domain);
}

bool PDB_secrets_clear_domain_protection(const char *domain)
{
	return secrets_clear_domain_protection(domain);
}

bool PDB_secrets_fetch_domain_sid(const char *domain, struct dom_sid  *sid)
{
	return secrets_fetch_domain_sid(domain, sid);
}

bool PDB_secrets_store_domain_guid(const char *domain, struct GUID *guid)
{
	return secrets_store_domain_guid(domain, guid);
}

bool PDB_secrets_fetch_domain_guid(const char *domain, struct GUID *guid)
{
	return secrets_fetch_domain_guid(domain, guid);
}
