/* 
   Unix SMB/CIFS implementation.

   interface functions for the sam database

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006

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
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/events/events.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "libcli/security/security.h"
#include "libcli/auth/libcli_auth.h"
#include "libcli/ldap/ldap_ndr.h"
#include "system/time.h"
#include "system/filesys.h"
#include "ldb_wrap.h"
#include "../lib/util/util_ldb.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/flags.h"
#include "param/param.h"
#include "lib/events/events.h"
#include "auth/credentials/credentials.h"
#include "param/secrets.h"

char *samdb_relative_path(struct ldb_context *ldb,
				 TALLOC_CTX *mem_ctx, 
				 const char *name) 
{
	const char *base_url = 
		(const char *)ldb_get_opaque(ldb, "ldb_url");
	char *path, *p, *full_name;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}
	path = talloc_strdup(mem_ctx, base_url);
	if (path == NULL) {
		return NULL;
	}
	if ( (p = strrchr(path, '/')) != NULL) {
		p[0] = '\0';
		full_name = talloc_asprintf(mem_ctx, "%s/%s", path, name);
	} else {
		full_name = talloc_asprintf(mem_ctx, "./%s", name);
	}
	talloc_free(path);
	return full_name;
}

struct cli_credentials *samdb_credentials(TALLOC_CTX *mem_ctx, 
					  struct tevent_context *event_ctx, 
					  struct loadparm_context *lp_ctx) 
{
	struct cli_credentials *cred = cli_credentials_init(mem_ctx);
	if (!cred) {
		return NULL;
	}
	cli_credentials_set_conf(cred, lp_ctx);

	/* We don't want to use krb5 to talk to our samdb - recursion
	 * here would be bad, and this account isn't in the KDC
	 * anyway */
	cli_credentials_set_kerberos_state(cred, CRED_DONT_USE_KERBEROS);

	if (!NT_STATUS_IS_OK(cli_credentials_set_secrets(cred, event_ctx, lp_ctx, NULL, NULL,
							 SECRETS_LDAP_FILTER))) {
		/* Perfectly OK - if not against an LDAP backend */
		return NULL;
	}
	return cred;
}

/*
  connect to the SAM database
  return an opaque context pointer on success, or NULL on failure
 */
struct ldb_context *samdb_connect(TALLOC_CTX *mem_ctx, 
				  struct tevent_context *ev_ctx,
				  struct loadparm_context *lp_ctx,
				  struct auth_session_info *session_info)
{
	struct ldb_context *ldb;
	ldb = ldb_wrap_connect(mem_ctx, ev_ctx, lp_ctx, 
			       lp_sam_url(lp_ctx), session_info,
			       samdb_credentials(mem_ctx, ev_ctx, lp_ctx), 
			       0, NULL);
	if (!ldb) {
		return NULL;
	}
	dsdb_make_schema_global(ldb);
	return ldb;
}

/*
  copy from a template record to a message
*/
int samdb_copy_template(struct ldb_context *ldb, 
			struct ldb_message *msg, const char *name,
			const char **errstring)
{
	struct ldb_result *res;
	struct ldb_message *t;
	int ret, i, j;
	struct ldb_context *templates_ldb;
	char *templates_ldb_path; 
	struct ldb_dn *basedn;
	struct tevent_context *event_ctx;
	struct loadparm_context *lp_ctx;

	templates_ldb = talloc_get_type(ldb_get_opaque(ldb, "templates_ldb"), struct ldb_context);

	if (!templates_ldb) {
		templates_ldb_path = samdb_relative_path(ldb, 
							 msg, 
							 "templates.ldb");
		if (!templates_ldb_path) {
			*errstring = talloc_asprintf(msg, "samdb_copy_template: ERROR: Failed to contruct path for template db");
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		event_ctx = ldb_get_event_context(ldb);
		lp_ctx = (struct loadparm_context *)ldb_get_opaque(ldb, "loadparm");

		/* FIXME: need to remove this wehn we finally pass the event
		 * context around in ldb */
		if (event_ctx == NULL) {
			event_ctx = s4_event_context_init(templates_ldb);
		}

		templates_ldb = ldb_wrap_connect(ldb, event_ctx, lp_ctx, 
						templates_ldb_path, NULL,
						NULL, 0, NULL);
		talloc_free(templates_ldb_path);
		if (!templates_ldb) {
			*errstring = talloc_asprintf(msg, "samdb_copy_template: ERROR: Failed to connect to templates db at: %s",
					     templates_ldb_path);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		ret = ldb_set_opaque(ldb, "templates_ldb", templates_ldb);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}
	*errstring = NULL;	

	basedn = ldb_dn_new(templates_ldb, ldb, "cn=Templates");
	if (!ldb_dn_add_child_fmt(basedn, "CN=Template%s", name)) {
		talloc_free(basedn);
		*errstring = talloc_asprintf(msg, "samdb_copy_template: ERROR: Failed to contruct DN for template '%s'", 
					     name);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	/* pull the template record */
	ret = ldb_search(templates_ldb, msg, &res, basedn, LDB_SCOPE_BASE, NULL, "distinguishedName=*");
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		*errstring = talloc_steal(msg, ldb_errstring(templates_ldb));
		return ret;
	}
	if (res->count != 1) {
		*errstring = talloc_asprintf(msg, "samdb_copy_template: ERROR: template '%s' matched %d records, expected 1", 
					     name, 
					     res->count);
		talloc_free(res);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	t = res->msgs[0];

	for (i = 0; i < t->num_elements; i++) {
		struct ldb_message_element *el = &t->elements[i];
		/* some elements should not be copied from the template */
		if (ldb_attr_cmp(el->name, "cn") == 0 ||
		    ldb_attr_cmp(el->name, "name") == 0 ||
		    ldb_attr_cmp(el->name, "objectClass") == 0 ||
		    ldb_attr_cmp(el->name, "sAMAccountName") == 0 ||
		    ldb_attr_cmp(el->name, "sAMAccountName") == 0 ||
		    ldb_attr_cmp(el->name, "distinguishedName") == 0 ||
		    ldb_attr_cmp(el->name, "objectGUID") == 0) {
			continue;
		}
		for (j = 0; j < el->num_values; j++) {
			ret = samdb_find_or_add_attribute(ldb, msg, el->name, 
							  (char *)el->values[j].data);
			if (ret) {
				*errstring = talloc_asprintf(msg, "Adding attribute %s failed.", el->name);
				talloc_free(res);
				return ret;
			}
		}
	}

	talloc_free(res);

	return LDB_SUCCESS;
}


/****************************************************************************
 Create the SID list for this user.
****************************************************************************/
NTSTATUS security_token_create(TALLOC_CTX *mem_ctx, 
			       struct tevent_context *ev_ctx, 
			       struct loadparm_context *lp_ctx,
			       struct dom_sid *user_sid,
			       struct dom_sid *group_sid, 
			       int n_groupSIDs,
			       struct dom_sid **groupSIDs, 
			       bool is_authenticated,
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
	status = samdb_privilege_setup(ev_ctx, lp_ctx, ptoken);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(ptoken);
		return status;
	}

	security_token_debug(10, ptoken);

	*token = ptoken;

	return NT_STATUS_OK;
}
