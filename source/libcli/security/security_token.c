/* 
   Unix SMB/CIFS implementation.

   security descriptror utility functions

   Copyright (C) Andrew Tridgell 		2004
      
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
#include "libcli/security/security.h"

/*
  return a blank security token
*/
struct security_token *security_token_initialise(TALLOC_CTX *mem_ctx)
{
	struct security_token *st;

	st = talloc_p(mem_ctx, struct security_token);
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
			       struct dom_sid *user_sid, struct dom_sid *group_sid, 
			       int n_groupSIDs, struct dom_sid **groupSIDs, 
			       BOOL is_guest, struct security_token **token)
{
	struct security_token *ptoken;
	int i;
	NTSTATUS status;

	ptoken = security_token_initialise(mem_ctx);
	if (ptoken == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ptoken->sids = talloc_array_p(ptoken, struct dom_sid *, n_groupSIDs + 5);
	if (!ptoken->sids) {
		return NT_STATUS_NO_MEMORY;
	}

	ptoken->user_sid = user_sid;
	ptoken->group_sid = group_sid;
	ptoken->privilege_mask = 0;

	ptoken->sids[0] = user_sid;
	ptoken->sids[1] = group_sid;

	/*
	 * Finally add the "standard" SIDs.
	 * The only difference between guest and "anonymous" (which we
	 * don't really support) is the addition of Authenticated_Users.
	 */
	ptoken->sids[2] = dom_sid_parse_talloc(mem_ctx, SID_WORLD);
	ptoken->sids[3] = dom_sid_parse_talloc(mem_ctx, SID_NT_NETWORK);
	ptoken->sids[4] = dom_sid_parse_talloc(mem_ctx, 
					       is_guest?SID_BUILTIN_GUESTS:
					       SID_NT_AUTHENTICATED_USERS);
	ptoken->num_sids = 5;

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
			ptoken->sids[ptoken->num_sids++] = groupSIDs[i];
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
	uint_t privilege;

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

	DEBUGADD(dbg_lev, (" Privileges (0x%08X%08X):\n",
			    (uint32_t)((token->privilege_mask & 0xFFFFFFFF00000000LL) >> 32),
			    (uint32_t)(token->privilege_mask & 0x00000000FFFFFFFFLL)));

	if (token->privilege_mask) {
		i = 0;
		for (privilege = 0; privilege < 64; privilege++) {
			uint64_t mask = sec_privilege_mask(privilege);

			if (token->privilege_mask & mask) {
				DEBUGADD(dbg_lev, ("  Privilege[%3lu]: %s\n", (unsigned long)i++, 
					sec_privilege_name(privilege)));
			}
		}
	}

	talloc_destroy(mem_ctx);
}
