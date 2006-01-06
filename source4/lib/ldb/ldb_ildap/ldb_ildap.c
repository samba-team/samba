/* 
   ldb database library - ildap backend

   Copyright (C) Andrew Tridgell  2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
  This is a ldb backend for the internal ldap client library in
  Samba4. By using this backend we are independent of a system ldap
  library
*/


#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/include/ldb_errors.h"
#include "libcli/ldap/ldap.h"
#include "libcli/ldap/ldap_client.h"
#include "lib/cmdline/popt_common.h"
#include "auth/auth.h"

struct ildb_private {
	struct ldap_connection *ldap;
	struct ldb_message *rootDSE;
	struct ldb_context *ldb;
};


/*
  map an ildap NTSTATUS to a ldb error code
*/
static int ildb_map_error(struct ildb_private *ildb, NTSTATUS status)
{
	if (NT_STATUS_IS_OK(status)) {
		return LDB_SUCCESS;
	}
	talloc_free(ildb->ldb->err_string);
	ildb->ldb->err_string = talloc_strdup(ildb, ldap_errstr(ildb->ldap, status));
	if (NT_STATUS_IS_LDAP(status)) {
		return NT_STATUS_LDAP_CODE(status);
	}
	return LDB_ERR_OPERATIONS_ERROR;
}

/*
  rename a record
*/
static int ildb_rename(struct ldb_module *module, const struct ldb_dn *olddn, const struct ldb_dn *newdn)
{
	TALLOC_CTX *local_ctx;
	struct ildb_private *ildb = module->private_data;
	int ret = 0;
	char *old_dn;
	char *newrdn, *parentdn;
	NTSTATUS status;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(olddn) || ldb_dn_is_special(newdn)) {
		return LDB_SUCCESS;
	}

	local_ctx = talloc_named(ildb, 0, "ildb_rename local context");
	if (local_ctx == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto failed;
	}

	old_dn = ldb_dn_linearize(local_ctx, olddn);
	if (old_dn == NULL) {
		ret = LDB_ERR_INVALID_DN_SYNTAX;
		goto failed;
	}

	newrdn = talloc_asprintf(local_ctx, "%s=%s",
					    newdn->components[0].name,
					    ldb_dn_escape_value(ildb, newdn->components[0].value));
	if (newrdn == NULL) {
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto failed;
	}

	parentdn = ldb_dn_linearize(local_ctx, ldb_dn_get_parent(ildb, newdn));
	if (parentdn == NULL) {
		ret = LDB_ERR_INVALID_DN_SYNTAX;
		goto failed;
	}

	status = ildap_rename(ildb->ldap, old_dn, newrdn, parentdn, True);
	ret = ildb_map_error(ildb, status);

failed:
	talloc_free(local_ctx);
	return ret;
}

/*
  delete a record
*/
static int ildb_delete(struct ldb_module *module, const struct ldb_dn *dn)
{
	struct ildb_private *ildb = module->private_data;
	char *del_dn;
	int ret = 0;
	NTSTATUS status;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(dn)) {
		return LDB_SUCCESS;
	}
	
	del_dn = ldb_dn_linearize(ildb, dn);
	if (del_dn == NULL) {
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	status = ildap_delete(ildb->ldap, del_dn);
	ret = ildb_map_error(ildb, status);

	talloc_free(del_dn);

	return ret;
}


static void ildb_rootdse(struct ldb_module *module);

/*
  search for matching records using a ldb_parse_tree
*/
static int ildb_search_bytree(struct ldb_module *module, const struct ldb_dn *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs,
			      struct ldb_control **control_req,
			      struct ldb_result **res)
{
	struct ildb_private *ildb = module->private_data;
	int count, i;
	struct ldap_message **ldapres, *msg;
	struct ldap_Control **controls = NULL;
	char *search_base;
	NTSTATUS status;

	if (scope == LDB_SCOPE_DEFAULT) {
		scope = LDB_SCOPE_SUBTREE;
	}
	
	if (base == NULL) {
		if (ildb->rootDSE == NULL) {
			ildb_rootdse(module);
		}
		if (ildb->rootDSE != NULL) {
			search_base = talloc_strdup(ildb,
						ldb_msg_find_string(ildb->rootDSE, 
								"defaultNamingContext", ""));
		} else {
			search_base = talloc_strdup(ildb, "");
		}
	} else {
		search_base = ldb_dn_linearize(ildb, base);
	}
	if (search_base == NULL) {
		ldb_set_errstring(module, talloc_asprintf(module, "Unable to determine baseDN"));
		return LDB_ERR_OTHER;
	}
	if (tree == NULL) {
		ldb_set_errstring(module, talloc_asprintf(module, "Invalid expression parse tree"));
		return LDB_ERR_OTHER;
	}

	(*res) = talloc(ildb, struct ldb_result);
	if (! *res) {
		return LDB_ERR_OTHER;
	}
	(*res)->count = 0;
	(*res)->msgs = NULL;
	(*res)->controls = NULL;

	status = ildap_search_bytree(ildb->ldap, search_base, scope, tree, attrs, 0,
				     (struct ldap_Control **)control_req,
				     &controls,
				     &ldapres);
	talloc_free(search_base);
	if (!NT_STATUS_IS_OK(status)) {
		ildb_map_error(ildb, status);
		return LDB_ERR_OTHER;
	}

	count = ildap_count_entries(ildb->ldap, ldapres);
	if (count == -1) {
		talloc_free(ldapres);
		return LDB_ERR_OTHER;
	}

	if (count == 0) {
		talloc_free(ldapres);
		return LDB_SUCCESS;
	}

	(*res)->msgs = talloc_array(*res, struct ldb_message *, count + 1);
	if (! (*res)->msgs) {
		talloc_free(ldapres);
		return LDB_ERR_OTHER;
	}

	(*res)->msgs[0] = NULL;

	/* loop over all messages */
	for (i=0;i<count;i++) {
		struct ldap_SearchResEntry *search;

		msg = ldapres[i];
		search = &msg->r.SearchResultEntry;

		(*res)->msgs[i] = talloc((*res)->msgs, struct ldb_message);
		if (!(*res)->msgs[i]) {
			goto failed;
		}
		(*res)->msgs[i+1] = NULL;

		(*res)->msgs[i]->dn = ldb_dn_explode_or_special((*res)->msgs[i], search->dn);
		if ((*res)->msgs[i]->dn == NULL) {
			goto failed;
		}
		(*res)->msgs[i]->num_elements = search->num_attributes;
		(*res)->msgs[i]->elements = talloc_steal((*res)->msgs[i], search->attributes);
		(*res)->msgs[i]->private_data = NULL;
	}

	talloc_free(ldapres);

	(*res)->count = count;

	if (controls) {
		(*res)->controls = (struct ldb_control **)talloc_steal(*res, controls);
	}

	return LDB_SUCCESS;

failed:
	if (*res) talloc_free(*res);
	return LDB_ERR_OTHER;
}


/*
  convert a ldb_message structure to a list of ldap_mod structures
  ready for ildap_add() or ildap_modify()
*/
static struct ldap_mod **ildb_msg_to_mods(struct ldb_context *ldb,
					  const struct ldb_message *msg, int use_flags)
{
	struct ldap_mod **mods;
	unsigned int i;
	int num_mods = 0;

	/* allocate maximum number of elements needed */
	mods = talloc_array(ldb, struct ldap_mod *, msg->num_elements+1);
	if (!mods) {
		errno = ENOMEM;
		return NULL;
	}
	mods[0] = NULL;

	for (i=0;i<msg->num_elements;i++) {
		const struct ldb_message_element *el = &msg->elements[i];

		mods[num_mods] = talloc(ldb, struct ldap_mod);
		if (!mods[num_mods]) {
			goto failed;
		}
		mods[num_mods+1] = NULL;
		mods[num_mods]->type = 0;
		mods[num_mods]->attrib = *el;
		if (use_flags) {
			switch (el->flags & LDB_FLAG_MOD_MASK) {
			case LDB_FLAG_MOD_ADD:
				mods[num_mods]->type = LDAP_MODIFY_ADD;
				break;
			case LDB_FLAG_MOD_DELETE:
				mods[num_mods]->type = LDAP_MODIFY_DELETE;
				break;
			case LDB_FLAG_MOD_REPLACE:
				mods[num_mods]->type = LDAP_MODIFY_REPLACE;
				break;
			}
		}
		num_mods++;
	}

	return mods;

failed:
	talloc_free(mods);
	return NULL;
}


/*
  add a record
*/
static int ildb_add(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_context *ldb = module->ldb;
	struct ildb_private *ildb = module->private_data;
	struct ldap_mod **mods;
	char *dn;
	int ret = 0;
	NTSTATUS status;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	mods = ildb_msg_to_mods(ldb, msg, 0);
	if (mods == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dn = ldb_dn_linearize(mods, msg->dn);
	if (dn == NULL) {
		talloc_free(mods);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	status = ildap_add(ildb->ldap, dn, mods);
	ret = ildb_map_error(ildb, status);

	talloc_free(mods);

	return ret;
}


/*
  modify a record
*/
static int ildb_modify(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_context *ldb = module->ldb;
	struct ildb_private *ildb = module->private_data;
	struct ldap_mod **mods;
	char *dn;
	int ret = 0;
	NTSTATUS status;

	/* ignore ltdb specials */
	if (ldb_dn_is_special(msg->dn)) {
		return LDB_SUCCESS;
	}

	mods = ildb_msg_to_mods(ldb, msg, 1);
	if (mods == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	dn = ldb_dn_linearize(mods, msg->dn);
	if (dn == NULL) {
		talloc_free(mods);
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	status = ildap_modify(ildb->ldap, dn, mods);
	ret = ildb_map_error(ildb, status);

	talloc_free(mods);

	return ret;
}

static int ildb_start_trans(struct ldb_module *module)
{
	/* TODO implement a local locking mechanism here */

	return 0;
}

static int ildb_end_trans(struct ldb_module *module)
{
	/* TODO implement a local transaction mechanism here */

	return 0;
}

static int ildb_del_trans(struct ldb_module *module)
{
	/* TODO implement a local locking mechanism here */

	return 0;
}

static int ildb_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return ildb_search_bytree(module,
					  req->op.search.base,
					  req->op.search.scope, 
					  req->op.search.tree, 
					  req->op.search.attrs, 
					  req->controls,
					  &req->op.search.res);

	case LDB_REQ_ADD:
		return ildb_add(module, req->op.add.message);

	case LDB_REQ_MODIFY:
		return ildb_modify(module, req->op.mod.message);

	case LDB_REQ_DELETE:
		return ildb_delete(module, req->op.del.dn);

	case LDB_REQ_RENAME:
		return ildb_rename(module,
					req->op.rename.olddn,
					req->op.rename.newdn);

	default:
		return -1;

	}
}

static int ildb_init_2(struct ldb_module *module)
{
	return LDB_SUCCESS;
}

static const struct ldb_module_ops ildb_ops = {
	.name              = "ldap",
	.request           = ildb_request,
	.start_transaction = ildb_start_trans,
	.end_transaction   = ildb_end_trans,
	.del_transaction   = ildb_del_trans,
	.second_stage_init = ildb_init_2
};


/*
  fetch the rootDSE
*/
static void ildb_rootdse(struct ldb_module *module)
{
	struct ildb_private *ildb = module->private_data;
	struct ldb_result *res = NULL;
	struct ldb_dn *empty_dn = ldb_dn_new(ildb);
	int ret;
	ret = ildb_search_bytree(module, empty_dn, LDB_SCOPE_BASE, 
				 ldb_parse_tree(empty_dn, "dn=dc=rootDSE"), 
				 NULL, NULL, &res);
	if (ret == LDB_SUCCESS && res->count == 1) {
		ildb->rootDSE = talloc_steal(ildb, res->msgs[0]);
	}
	if (ret == LDB_SUCCESS) talloc_free(res);
	talloc_free(empty_dn);
}


/*
  connect to the database
*/
int ildb_connect(struct ldb_context *ldb, const char *url, 
		 unsigned int flags, const char *options[])
{
	struct ildb_private *ildb = NULL;
	NTSTATUS status;
	struct cli_credentials *creds;

	ildb = talloc(ldb, struct ildb_private);
	if (!ildb) {
		ldb_oom(ldb);
		goto failed;
	}

	ildb->rootDSE = NULL;
	ildb->ldb     = ldb;

	ildb->ldap = ldap_new_connection(ildb, ldb_get_opaque(ldb, "EventContext"));
	if (!ildb->ldap) {
		ldb_oom(ldb);
		goto failed;
	}

	status = ldap_connect(ildb->ldap, url);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Failed to connect to ldap URL '%s' - %s\n",
			  url, ldap_errstr(ildb->ldap, status));
		goto failed;
	}

	ldb->modules = talloc(ldb, struct ldb_module);
	if (!ldb->modules) {
		ldb_oom(ldb);
		goto failed;
	}
	ldb->modules->ldb = ldb;
	ldb->modules->prev = ldb->modules->next = NULL;
	ldb->modules->private_data = ildb;
	ldb->modules->ops = &ildb_ops;

	/* caller can optionally setup credentials using the opaque token 'credentials' */
	creds = talloc_get_type(ldb_get_opaque(ldb, "credentials"), struct cli_credentials);
	if (creds == NULL) {
		struct auth_session_info *session_info = talloc_get_type(ldb_get_opaque(ldb, "sessionInfo"), struct auth_session_info);
		if (session_info) {
			creds = session_info->credentials;
		}
	}

	if (creds != NULL && cli_credentials_authentication_requested(creds)) {
		const char *bind_dn = cli_credentials_get_bind_dn(creds);
		if (bind_dn) {
			const char *password = cli_credentials_get_password(creds);
			status = ldap_bind_simple(ildb->ldap, bind_dn, password);
			if (!NT_STATUS_IS_OK(status)) {
				ldb_debug(ldb, LDB_DEBUG_ERROR, "Failed to bind - %s\n",
					  ldap_errstr(ildb->ldap, status));
				goto failed;
			}
		} else {
			status = ldap_bind_sasl(ildb->ldap, creds);
			if (!NT_STATUS_IS_OK(status)) {
				ldb_debug(ldb, LDB_DEBUG_ERROR, "Failed to bind - %s\n",
					  ldap_errstr(ildb->ldap, status));
				goto failed;
			}
		}
	}

	return 0;

failed:
	if (ldb->modules) {
		ldb->modules->private_data = NULL;
	}
	talloc_free(ildb);
	return -1;
}

