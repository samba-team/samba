/* 
   Unix SMB/CIFS implementation.

   security descriptror utility functions

   Copyright (C) Andrew Tridgell 		2004
   Copyright (C) Stefan Metzmacher 		2005
      
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
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"

/*
  return a blank security token
*/
struct security_token *security_token_initialise(TALLOC_CTX *mem_ctx)
{
	struct security_token *st;

	st = talloc(mem_ctx, struct security_token);
	if (!st) {
		return NULL;
	}

	st->user_sid = NULL;
	st->group_sid = NULL;
	st->num_sids = 0;
	st->sids = NULL;
	st->privilege_mask = 0;

	return st;
}

/****************************************************************************
 Create the SID list for this user.
****************************************************************************/
NTSTATUS security_token_create(TALLOC_CTX *mem_ctx, 
			       struct dom_sid *user_sid,
			       struct dom_sid *group_sid, 
			       int n_groupSIDs,
			       struct dom_sid **groupSIDs, 
			       BOOL is_authenticated,
			       struct security_token **token)
{
	struct security_token *ptoken;
	int i;
	NTSTATUS status;

	ptoken = security_token_initialise(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(ptoken);

	ptoken->sids = talloc_array(ptoken, struct dom_sid *, n_groupSIDs + 5);
	NT_STATUS_HAVE_NO_MEMORY(ptoken->sids);

	ptoken->user_sid = talloc_reference(ptoken, user_sid);
	ptoken->group_sid = talloc_reference(ptoken, group_sid);
	ptoken->privilege_mask = 0;

	ptoken->sids[0] = ptoken->user_sid;
	ptoken->sids[1] = ptoken->group_sid;

	/*
	 * Finally add the "standard" SIDs.
	 * The only difference between guest and "anonymous"
	 * is the addition of Authenticated_Users.
	 */
	ptoken->sids[2] = dom_sid_parse_talloc(ptoken->sids, SID_WORLD);
	NT_STATUS_HAVE_NO_MEMORY(ptoken->sids[2]);
	ptoken->sids[3] = dom_sid_parse_talloc(ptoken->sids, SID_NT_NETWORK);
	NT_STATUS_HAVE_NO_MEMORY(ptoken->sids[3]);
	ptoken->num_sids = 4;

	if (is_authenticated) {
		ptoken->sids[4] = dom_sid_parse_talloc(ptoken->sids, SID_NT_AUTHENTICATED_USERS);
		NT_STATUS_HAVE_NO_MEMORY(ptoken->sids[4]);
		ptoken->num_sids++;
	}

	for (i = 0; i < n_groupSIDs; i++) {
		size_t check_sid_idx;
		for (check_sid_idx = 1; 
		     check_sid_idx < ptoken->num_sids; 
		     check_sid_idx++) {
			if (dom_sid_equal(ptoken->sids[check_sid_idx], groupSIDs[i])) {
				break;
			}
		}

		if (check_sid_idx == ptoken->num_sids) {
			ptoken->sids[ptoken->num_sids++] = talloc_reference(ptoken->sids, groupSIDs[i]);
		}
	}

	/* setup the privilege mask for this token */
	status = samdb_privilege_setup(ptoken);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(ptoken);
		return status;
	}

	security_token_debug(10, ptoken);

	*token = ptoken;

	return NT_STATUS_OK;
}

/****************************************************************************
 prints a struct security_token to debug output.
****************************************************************************/
void security_token_debug(int dbg_lev, const struct security_token *token)
{
	TALLOC_CTX *mem_ctx;
	int i;

	if (!token) {
		DEBUG(dbg_lev, ("Security token: (NULL)\n"));
		return;
	}

	mem_ctx = talloc_init("security_token_debug()");
	if (!mem_ctx) {
		return;
	}

	DEBUG(dbg_lev, ("Security token of user %s\n",
				    dom_sid_string(mem_ctx, token->user_sid) ));
	DEBUGADD(dbg_lev, (" SIDs (%lu):\n", 
				       (unsigned long)token->num_sids));
	for (i = 0; i < token->num_sids; i++) {
		DEBUGADD(dbg_lev, ("  SID[%3lu]: %s\n", (unsigned long)i, 
			   dom_sid_string(mem_ctx, token->sids[i])));
	}

	sec_privilege_debug(dbg_lev, token);

	talloc_free(mem_ctx);
}

/* These really should be cheaper... */

BOOL security_token_is_sid(struct security_token *token, const struct dom_sid *sid)
{
	if (dom_sid_equal(token->user_sid, sid)) {
		return True;
	}
	return False;
}

BOOL security_token_is_sid_string(struct security_token *token, const char *sid_string)
{
	BOOL ret;
	struct dom_sid *sid = dom_sid_parse_talloc(token, sid_string);
	if (!sid) return False;

	ret = security_token_is_sid(token, sid);

	talloc_free(sid);
	return ret;
}

BOOL security_token_is_system(struct security_token *token) 
{
	return security_token_is_sid_string(token, SID_NT_SYSTEM);
}

BOOL security_token_is_anonymous(struct security_token *token) 
{
	return security_token_is_sid_string(token, SID_NT_ANONYMOUS);
}

BOOL security_token_has_sid(struct security_token *token, struct dom_sid *sid)
{
	int i;
	for (i = 0; i < token->num_sids; i++) {
		if (dom_sid_equal(token->sids[i], sid)) {
			return True;
		}
	}
	return False;
}

BOOL security_token_has_sid_string(struct security_token *token, const char *sid_string)
{
	BOOL ret;
	struct dom_sid *sid = dom_sid_parse_talloc(token, sid_string);
	if (!sid) return False;

	ret = security_token_has_sid(token, sid);

	talloc_free(sid);
	return ret;
}

BOOL security_token_has_builtin_administrators(struct security_token *token)
{
	return security_token_has_sid_string(token, SID_BUILTIN_ADMINISTRATORS);
}

BOOL security_token_has_nt_authenticated_users(struct security_token *token)
{
	return security_token_has_sid_string(token, SID_NT_AUTHENTICATED_USERS);
}
