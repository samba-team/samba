/* 
   Unix SMB/CIFS implementation.

   manipulate privilege records in samdb

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
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/ldb/include/ldb.h"

/*
  add privilege bits for one sid to a security_token
*/
static NTSTATUS samdb_privilege_setup_sid(void *samctx, TALLOC_CTX *mem_ctx,
					  const struct dom_sid *sid, 
					  uint64_t *mask)
{
	char *sidstr;
	const char * const attrs[] = { "privilege", NULL };
	struct ldb_message **res = NULL;
	struct ldb_message_element *el;
	int ret, i;
	
	*mask = 0;

	sidstr = dom_sid_string(mem_ctx, sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_search(samctx, mem_ctx, NULL, &res, attrs, "objectSid=%s", sidstr);
	if (ret != 1) {
		talloc_free(sidstr);
		/* not an error to not match */
		return NT_STATUS_OK;
	}

	el = ldb_msg_find_element(res[0], "privilege");
	if (el == NULL) {
		talloc_free(sidstr);
		return NT_STATUS_OK;
	}

	for (i=0;i<el->num_values;i++) {
		const char *priv_str = el->values[i].data;
		int privilege = sec_privilege_id(priv_str);
		if (privilege == -1) {
			DEBUG(1,("Unknown privilege '%s' in samdb\n",
				 priv_str));
			continue;
		}
		*mask |= sec_privilege_mask(privilege);
	}

	return NT_STATUS_OK;
}

/*
  setup the privilege mask for this security token based on our
  local SAM
*/
NTSTATUS samdb_privilege_setup(struct security_token *token)
{
	void *samctx;
	TALLOC_CTX *mem_ctx = talloc(token, 0);
	int i;
	NTSTATUS status;

	samctx = samdb_connect(mem_ctx);
	if (samctx == NULL) {
		talloc_free(mem_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	token->privilege_mask = 0;
	
	for (i=0;i<token->num_sids;i++) {
		uint64_t mask;
		status = samdb_privilege_setup_sid(samctx, mem_ctx, 
						   token->sids[i], &mask);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(mem_ctx);
			return status;
		}
		token->privilege_mask |= mask;
	}

	talloc_free(mem_ctx);

	return NT_STATUS_OK;	
}
