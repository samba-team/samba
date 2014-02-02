/*
   Unix SMB/CIFS implementation.

   Deal with unix elements in the security token

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett 2011

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
#include "auth/auth.h"
#include "libcli/wbclient/wbclient.h"
#include "param/param.h"

/*
  form a security_unix_token from the current security_token
*/
NTSTATUS security_token_to_unix_token(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct security_token *token,
				      struct security_unix_token **sec)
{
	uint32_t s, g;
	NTSTATUS status;
	struct id_map *ids;

	/* we can't do unix security without a user and group */
	if (token->num_sids < 2) {
		return NT_STATUS_ACCESS_DENIED;
	}

	*sec = talloc_zero(mem_ctx, struct security_unix_token);
	if (*sec == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ids = talloc_zero_array(mem_ctx, struct id_map, token->num_sids);
	NT_STATUS_HAVE_NO_MEMORY(ids);

	for (s=0; s < token->num_sids; s++) {
		ids[s].sid = &token->sids[s];
		ids[s].status = ID_UNKNOWN;
	}

	status = wbc_sids_to_xids(ev, ids, token->num_sids);
	NT_STATUS_NOT_OK_RETURN(status);

	g = token->num_sids;
	if (ids[0].xid.type != ID_TYPE_BOTH) {
		g--;
	}
	(*sec)->ngroups = g;
	(*sec)->groups = talloc_array(*sec, gid_t, (*sec)->ngroups);
	NT_STATUS_HAVE_NO_MEMORY((*sec)->groups);

	g=0;
	if (ids[0].xid.type == ID_TYPE_BOTH) {
		(*sec)->uid = ids[0].xid.id;
		(*sec)->groups[g] = ids[0].xid.id;
		g++;
	} else if (ids[0].xid.type == ID_TYPE_UID) {
		(*sec)->uid = ids[0].xid.id;
	} else {
		char *sid_str = dom_sid_string(mem_ctx, ids[0].sid);
		DEBUG(0, ("Unable to convert first SID (%s) in user token to a UID.  Conversion was returned as type %d, full token:\n",
			  sid_str, (int)ids[0].xid.type));
		security_token_debug(0, 0, token);
		talloc_free(sid_str);
		return NT_STATUS_INVALID_SID;
	}

	if (ids[1].xid.type == ID_TYPE_BOTH ||
	    ids[1].xid.type == ID_TYPE_GID) {
		(*sec)->gid = ids[1].xid.id;
		(*sec)->groups[g] = ids[1].xid.id;
		g++;
	} else {
		char *sid_str = dom_sid_string(mem_ctx, ids[1].sid);
		DEBUG(0, ("Unable to convert second SID (%s) in user token to a GID.  Conversion was returned as type %d, full token:\n",
			  sid_str, (int)ids[1].xid.type));
		security_token_debug(0, 0, token);
		talloc_free(sid_str);
		return NT_STATUS_INVALID_SID;
	}

	for (s=2; s < token->num_sids; s++) {
		if (ids[s].xid.type == ID_TYPE_BOTH ||
		    ids[s].xid.type == ID_TYPE_GID) {
			(*sec)->groups[g] = ids[s].xid.id;
			g++;
		} else {
			char *sid_str = dom_sid_string(mem_ctx, ids[s].sid);
			DEBUG(0, ("Unable to convert SID (%s) at index %u in user token to a GID.  Conversion was returned as type %d, full token:\n",
				  sid_str, (unsigned int)s, (int)ids[s].xid.type));
			security_token_debug(0, 0, token);
			talloc_free(sid_str);
			return NT_STATUS_INVALID_SID;
		}
	}

	DEBUG(5, ("Successfully converted security token to a unix token:"));
	security_token_debug(0, 5, token);
	TALLOC_FREE(ids);

	return NT_STATUS_OK;
}

/*
  Fill in the auth_user_info_unix and auth_unix_token elements in a struct session_info
*/
NTSTATUS auth_session_info_fill_unix(struct tevent_context *ev,
				     struct loadparm_context *lp_ctx,
				     const char *original_user_name,
				     struct auth_session_info *session_info)
{
	char *su;
	size_t len;
	NTSTATUS status = security_token_to_unix_token(session_info, ev,
						       session_info->security_token,
						       &session_info->unix_token);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	session_info->unix_info = talloc_zero(session_info, struct auth_user_info_unix);
	NT_STATUS_HAVE_NO_MEMORY(session_info->unix_info);

	session_info->unix_info->unix_name = talloc_asprintf(session_info->unix_info,
							     "%s%s%s", session_info->info->domain_name,
							     lpcfg_winbind_separator(lp_ctx),
							     session_info->info->account_name);
	NT_STATUS_HAVE_NO_MEMORY(session_info->unix_info->unix_name);

	len = strlen(original_user_name) + 1;
	session_info->unix_info->sanitized_username = su = talloc_array(session_info->unix_info, char, len);
	NT_STATUS_HAVE_NO_MEMORY(su);

	alpha_strcpy(su, original_user_name,
		     ". _-$", len);

	return NT_STATUS_OK;
}
