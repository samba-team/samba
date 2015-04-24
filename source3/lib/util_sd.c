/*
   Unix SMB/CIFS implementation.
   Security Descriptor (SD) helper functions

   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter      2000
   Copyright (C) Jeremy Allison  2000
   Copyright (C) Jelmer Vernooij 2003

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
#include "libsmb/libsmb.h"
#include "util_sd.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "../libcli/security/security.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_client/cli_lsarpc.h"

/* Open cli connection and policy handle */
static NTSTATUS cli_lsa_lookup_sid(struct cli_state *cli,
				   const struct dom_sid *sid,
				   TALLOC_CTX *mem_ctx,
				   enum lsa_SidType *type,
				   char **domain, char **name)
{
	uint16 orig_cnum = cli_state_get_tid(cli);
	struct rpc_pipe_client *p = NULL;
	struct policy_handle handle;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	enum lsa_SidType *types;
	char **domains;
	char **names;

	status = cli_tree_connect(cli, "IPC$", "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		goto tcon_fail;
	}

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_lsarpc,
					  &p);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = rpccli_lsa_open_policy(p, talloc_tos(), True,
					GENERIC_EXECUTE_ACCESS, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = rpccli_lsa_lookup_sids(p, talloc_tos(), &handle, 1, sid,
					&domains, &names, &types);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	*type = types[0];
	*domain = talloc_move(mem_ctx, &domains[0]);
	*name = talloc_move(mem_ctx, &names[0]);

	status = NT_STATUS_OK;
 fail:
	TALLOC_FREE(p);
	cli_tdis(cli);
 tcon_fail:
	cli_state_set_tid(cli, orig_cnum);
	TALLOC_FREE(frame);
	return status;
}

/* convert a SID to a string, either numeric or username/group */
void SidToString(struct cli_state *cli, fstring str, const struct dom_sid *sid,
		 bool numeric)
{
	char *domain = NULL;
	char *name = NULL;
	enum lsa_SidType type;
	NTSTATUS status;

	sid_to_fstring(str, sid);

	if (numeric) {
		return;
	}

	status = cli_lsa_lookup_sid(cli, sid, talloc_tos(), &type,
				    &domain, &name);

	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	if (*domain) {
		slprintf(str, sizeof(fstring) - 1, "%s%s%s",
			domain, lp_winbind_separator(), name);
	} else {
		fstrcpy(str, name);
	}
}

static NTSTATUS cli_lsa_lookup_name(struct cli_state *cli,
				    const char *name,
				    enum lsa_SidType *type,
				    struct dom_sid *sid)
{
	uint16 orig_cnum = cli_state_get_tid(cli);
	struct rpc_pipe_client *p;
	struct policy_handle handle;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	struct dom_sid *sids;
	enum lsa_SidType *types;

	status = cli_tree_connect(cli, "IPC$", "?????", "", 0);
	if (!NT_STATUS_IS_OK(status)) {
		goto tcon_fail;
	}

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_lsarpc,
					  &p);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = rpccli_lsa_open_policy(p, talloc_tos(), True,
					GENERIC_EXECUTE_ACCESS, &handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = rpccli_lsa_lookup_names(p, talloc_tos(), &handle, 1, &name,
					 NULL, 1, &sids, &types);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	*type = types[0];
	*sid = sids[0];

	status = NT_STATUS_OK;
 fail:
	TALLOC_FREE(p);
	cli_tdis(cli);
 tcon_fail:
	cli_state_set_tid(cli, orig_cnum);
	TALLOC_FREE(frame);
	return status;
}

/* convert a string to a SID, either numeric or username/group */
bool StringToSid(struct cli_state *cli, struct dom_sid *sid, const char *str)
{
	enum lsa_SidType type;

	if (string_to_sid(sid, str)) {
		return true;
	}

	return NT_STATUS_IS_OK(cli_lsa_lookup_name(cli, str, &type, sid));
}
