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
#include "libcli/ldap/ldap.h"
#include "libcli/ldap/ldap_client.h"
#include "lib/cmdline/popt_common.h"

struct ildb_private {
	const char *basedn;
	struct ldap_connection *ldap;
	NTSTATUS last_rc;
};

/*
  rename a record
*/
static int ildb_rename(struct ldb_module *module, const char *olddn, const char *newdn)
{
	struct ildb_private *ildb = module->private_data;
	int ret = 0;
	char *newrdn, *p;
	const char *parentdn = "";

	/* ignore ltdb specials */
	if (olddn[0] == '@' ||newdn[0] == '@') {
		return 0;
	}

	newrdn = talloc_strdup(ildb, newdn);
	if (!newrdn) {
		return -1;
	}

	p = strchr(newrdn, ',');
	if (p) {
		*p++ = '\0';
		parentdn = p;
	}

	ildb->last_rc = ildap_rename(ildb->ldap, olddn, newrdn, parentdn, True);
	if (!NT_STATUS_IS_OK(ildb->last_rc)) {
		ret = -1;
	}

	talloc_free(newrdn);

	return ret;
}

/*
  delete a record
*/
static int ildb_delete(struct ldb_module *module, const char *dn)
{
	struct ildb_private *ildb = module->private_data;
	int ret = 0;

	/* ignore ltdb specials */
	if (dn[0] == '@') {
		return 0;
	}
	
	ildb->last_rc = ildap_delete(ildb->ldap, dn);
	if (!NT_STATUS_IS_OK(ildb->last_rc)) {
		ret = -1;
	}

	return ret;
}


/*
  search for matching records
*/
static int ildb_search(struct ldb_module *module, const char *base,
		       enum ldb_scope scope, const char *expression,
		       const char * const *attrs, struct ldb_message ***res)
{
	struct ildb_private *ildb = module->private_data;
	int count, i;
	struct ldap_message **ldapres, *msg;

	if (scope == LDB_SCOPE_DEFAULT) {
		scope = LDB_SCOPE_SUBTREE;
	}
	
	if (base == NULL) {
		base = "";
	}

	if (expression == NULL || expression[0] == '\0') {
		expression = "objectClass=*";
	}

	ildb->last_rc = ildap_search(ildb->ldap, base, scope, expression, attrs, 
				     0, &ldapres);
	if (!NT_STATUS_IS_OK(ildb->last_rc)) {
		return -1;
	}

	count = ildap_count_entries(ildb->ldap, ldapres);
	if (count == -1 || count == 0) {
		talloc_free(ldapres);
		return count;
	}

	(*res) = talloc_array(ildb, struct ldb_message *, count+1);
	if (! *res) {
		talloc_free(ldapres);
		return -1;
	}

	(*res)[0] = NULL;

	/* loop over all messages */
	for (i=0;i<count;i++) {
		struct ldap_SearchResEntry *search;

		msg = ldapres[i];
		search = &msg->r.SearchResultEntry;

		(*res)[i] = talloc(*res, struct ldb_message);
		if (!(*res)[i]) {
			goto failed;
		}
		(*res)[i+1] = NULL;

		(*res)[i]->dn = talloc_steal((*res)[i], search->dn);
		(*res)[i]->num_elements = search->num_attributes;
		(*res)[i]->elements = talloc_steal((*res)[i], search->attributes);
		(*res)[i]->private_data = NULL;
	}

	talloc_free(ldapres);

	return count;

failed:
	if (*res) talloc_free(*res);
	return -1;
}


/*
  search for matching records using a ldb_parse_tree
*/
static int ildb_search_bytree(struct ldb_module *module, const char *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs, struct ldb_message ***res)
{
	struct ildb_private *ildb = module->private_data;
	char *expression;
	int ret;

	expression = ldb_filter_from_tree(ildb, tree);
	if (expression == NULL) {
		return -1;
	}
	ret = ildb_search(module, base, scope, expression, attrs, res);
	talloc_free(expression);
	return ret;
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
	int ret = 0;

	/* ignore ltdb specials */
	if (msg->dn[0] == '@') {
		return 0;
	}

	mods = ildb_msg_to_mods(ldb, msg, 0);

	ildb->last_rc = ildap_add(ildb->ldap, msg->dn, mods);
	if (!NT_STATUS_IS_OK(ildb->last_rc)) {
		ret = -1;
	}

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
	int ret = 0;

	/* ignore ltdb specials */
	if (msg->dn[0] == '@') {
		return 0;
	}

	mods = ildb_msg_to_mods(ldb, msg, 1);

	ildb->last_rc = ildap_modify(ildb->ldap, msg->dn, mods);
	if (!NT_STATUS_IS_OK(ildb->last_rc)) {
		ret = -1;
	}

	talloc_free(mods);

	return ret;
}

static int ildb_lock(struct ldb_module *module, const char *lockname)
{
	int ret = 0;

	if (lockname == NULL) {
		return -1;
	}

	/* TODO implement a local locking mechanism here */

	return ret;
}

static int ildb_unlock(struct ldb_module *module, const char *lockname)
{
	int ret = 0;

	if (lockname == NULL) {
		return -1;
	}

	/* TODO implement a local unlocking mechanism here */

	return ret;
}

/*
  return extended error information
*/
static const char *ildb_errstring(struct ldb_module *module)
{
	struct ildb_private *ildb = module->private_data;
	return ldap_errstr(ildb->ldap, ildb->last_rc);
}


static const struct ldb_module_ops ildb_ops = {
	.name          = "ldap",
	.search        = ildb_search,
	.search_bytree = ildb_search_bytree,
	.add_record    = ildb_add,
	.modify_record = ildb_modify,
	.delete_record = ildb_delete,
	.rename_record = ildb_rename,
	.named_lock    = ildb_lock,
	.named_unlock  = ildb_unlock,
	.errstring     = ildb_errstring
};


/*
  connect to the database
*/
int ildb_connect(struct ldb_context *ldb, const char *url, 
		 unsigned int flags, const char *options[])
{
	struct ildb_private *ildb = NULL;
	NTSTATUS status;

	ildb = talloc(ldb, struct ildb_private);
	if (!ildb) {
		ldb_oom(ldb);
		goto failed;
	}

	ildb->ldap = ldap_new_connection(ildb, NULL);
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

	if (cmdline_credentials->username_obtained > CRED_GUESSED) {
		status = ldap_bind_sasl(ildb->ldap, cmdline_credentials);
		if (!NT_STATUS_IS_OK(status)) {
			ldb_debug(ldb, LDB_DEBUG_ERROR, "Failed to bind - %s\n",
				  ldap_errstr(ildb->ldap, status));
			goto failed;
		}
	}

	return 0;

failed:
	talloc_free(ildb);
	return -1;
}

