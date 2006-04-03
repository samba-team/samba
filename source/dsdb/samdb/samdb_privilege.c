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
#include "libcli/ldap/ldap.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "libcli/security/security.h"
#include "db_wrap.h"

/*
  add privilege bits for one sid to a security_token
*/
static NTSTATUS samdb_privilege_setup_sid(void *samctx, TALLOC_CTX *mem_ctx,
					  struct security_token *token,
					  const struct dom_sid *sid)
{
	const char * const attrs[] = { "privilege", NULL };
	struct ldb_message **res = NULL;
	struct ldb_message_element *el;
	int ret, i;
	char *sidstr;

	sidstr = ldap_encode_ndr_dom_sid(mem_ctx, sid);
	NT_STATUS_HAVE_NO_MEMORY(sidstr);

	ret = gendb_search(samctx, mem_ctx, NULL, &res, attrs, "objectSid=%s", sidstr);
	talloc_free(sidstr);
	if (ret != 1) {
		/* not an error to not match */
		return NT_STATUS_OK;
	}

	el = ldb_msg_find_element(res[0], "privilege");
	if (el == NULL) {
		return NT_STATUS_OK;
	}

	for (i=0;i<el->num_values;i++) {
		const char *priv_str = (const char *)el->values[i].data;
		enum sec_privilege privilege = sec_privilege_id(priv_str);
		if (privilege == -1) {
			DEBUG(1,("Unknown privilege '%s' in samdb\n",
				 priv_str));
			continue;
		}
		security_token_set_privilege(token, privilege);
	}

	return NT_STATUS_OK;
}

/*
  setup the privilege mask for this security token based on our
  local SAM
*/
_PUBLIC_ NTSTATUS samdb_privilege_setup(struct security_token *token)
{
	void *samctx;
	TALLOC_CTX *mem_ctx;
	int i;
	NTSTATUS status;

	/* Shortcuts to prevent recursion and avoid lookups */
	if (security_token_is_system(token)) {
		token->privilege_mask = ~0;
		return NT_STATUS_OK;
	}

	if (security_token_is_anonymous(token)) {
		token->privilege_mask = 0;
		return NT_STATUS_OK;
	}

	mem_ctx = talloc_new(token);
	samctx = samdb_connect(mem_ctx, system_session(mem_ctx));
	if (samctx == NULL) {
		talloc_free(mem_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	token->privilege_mask = 0;
	
	for (i=0;i<token->num_sids;i++) {
		status = samdb_privilege_setup_sid(samctx, mem_ctx,
						   token, token->sids[i]);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(mem_ctx);
			return status;
		}
	}

	talloc_free(mem_ctx);

	return NT_STATUS_OK;	
}
