/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

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
 *  Name: ldb
 *
 *  Component: ldb ldap backend
 *
 *  Description: core files for LDAP backend
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/ldb_ldap/ldb_ldap.h"

#if 0
/*
  we don't need this right now, but will once we add some backend 
  options
*/

/*
  find an option in an option list (a null terminated list of strings)

  this assumes the list is short. If it ever gets long then we really
  should do this in some smarter way
 */
static const char *lldb_option_find(const struct lldb_private *lldb, const char *name)
{
	int i;
	size_t len = strlen(name);

	if (!lldb->options) return NULL;

	for (i=0;lldb->options[i];i++) {		
		if (strncmp(lldb->options[i], name, len) == 0 &&
		    lldb->options[i][len] == '=') {
			return &lldb->options[i][len+1];
		}
	}

	return NULL;
}
#endif

/*
  close/free the connection
*/
static int lldb_close(struct ldb_module *module)
{
	struct ldb_context *ldb = module->ldb;
	talloc_free(ldb);
	return 0;
}

/*
  rename a record
*/
static int lldb_rename(struct ldb_module *module, const char *olddn, const char *newdn)
{
	struct lldb_private *lldb = module->private_data;
	int ret = 0;
	char *newrdn, *p;
	const char *parentdn = "";
	TALLOC_CTX *mem_ctx = talloc(lldb, 0);

	/* ignore ltdb specials */
	if (olddn[0] == '@' ||newdn[0] == '@') {
		return 0;
	}

	newrdn = talloc_strdup(mem_ctx, newdn);
	if (!newrdn) {
		return -1;
	}

	p = strchr(newrdn, ',');
	if (p) {
		*p++ = '\0';
		parentdn = p;
	}

	lldb->last_rc = ldap_rename_s(lldb->ldap, olddn, newrdn, parentdn, 1, NULL, NULL);
	if (lldb->last_rc != LDAP_SUCCESS) {
		ret = -1;
	}

	talloc_free(mem_ctx);

	return ret;
}

/*
  delete a record
*/
static int lldb_delete(struct ldb_module *module, const char *dn)
{
	struct lldb_private *lldb = module->private_data;
	int ret = 0;

	/* ignore ltdb specials */
	if (dn[0] == '@') {
		return 0;
	}
	
	lldb->last_rc = ldap_delete_s(lldb->ldap, dn);
	if (lldb->last_rc != LDAP_SUCCESS) {
		ret = -1;
	}

	return ret;
}

/*
  free a search result
*/
static int lldb_search_free(struct ldb_module *module, struct ldb_message **res)
{
	talloc_free(res);
	return 0;
}


/*
  add a single set of ldap message values to a ldb_message
*/
static int lldb_add_msg_attr(struct ldb_context *ldb,
			     struct ldb_message *msg, 
			     const char *attr, struct berval **bval)
{
	int count, i;
	struct ldb_message_element *el;

	count = ldap_count_values_len(bval);

	if (count <= 0) {
		return -1;
	}

	el = talloc_realloc_p(msg, msg->elements, struct ldb_message_element, 
			      msg->num_elements + 1);
	if (!el) {
		errno = ENOMEM;
		return -1;
	}

	msg->elements = el;

	el = &msg->elements[msg->num_elements];

	el->name = talloc_strdup(msg->elements, attr);
	if (!el->name) {
		errno = ENOMEM;
		return -1;
	}
	el->flags = 0;

	el->num_values = 0;
	el->values = talloc_array_p(msg->elements, struct ldb_val, count);
	if (!el->values) {
		errno = ENOMEM;
		return -1;
	}

	for (i=0;i<count;i++) {
		el->values[i].data = talloc_memdup(el->values, bval[i]->bv_val, bval[i]->bv_len);
		if (!el->values[i].data) {
			return -1;
		}
		el->values[i].length = bval[i]->bv_len;
		el->num_values++;
	}

	msg->num_elements++;

	return 0;
}

/*
  search for matching records
*/
static int lldb_search(struct ldb_module *module, const char *base,
		       enum ldb_scope scope, const char *expression,
		       const char * const *attrs, struct ldb_message ***res)
{
	struct ldb_context *ldb = module->ldb;
	struct lldb_private *lldb = module->private_data;
	int count, msg_count;
	LDAPMessage *ldapres, *msg;

	if (base == NULL) {
		base = "";
	}

	lldb->last_rc = ldap_search_s(lldb->ldap, base, (int)scope, 
				      expression, 
				      discard_const_p(char *, attrs), 
				      0, &ldapres);
	if (lldb->last_rc != LDAP_SUCCESS) {
		return -1;
	}

	count = ldap_count_entries(lldb->ldap, ldapres);
	if (count == -1 || count == 0) {
		ldap_msgfree(ldapres);
		return count;
	}

	(*res) = talloc_array_p(lldb, struct ldb_message *, count+1);
	if (! *res) {
		ldap_msgfree(ldapres);
		errno = ENOMEM;
		return -1;
	}

	(*res)[0] = NULL;

	msg_count = 0;

	/* loop over all messages */
	for (msg=ldap_first_entry(lldb->ldap, ldapres); 
	     msg; 
	     msg=ldap_next_entry(lldb->ldap, msg)) {
		BerElement *berptr = NULL;
		char *attr, *dn;

		if (msg_count == count) {
			/* hmm, got too many? */
			ldb_debug(ldb, LDB_DEBUG_FATAL, "Fatal: ldap message count inconsistent\n");
			break;
		}

		(*res)[msg_count] = talloc_p(*res, struct ldb_message);
		if (!(*res)[msg_count]) {
			goto failed;
		}
		(*res)[msg_count+1] = NULL;

		dn = ldap_get_dn(lldb->ldap, msg);
		if (!dn) {
			goto failed;
		}

		(*res)[msg_count]->dn = talloc_strdup((*res)[msg_count], dn);
		ldap_memfree(dn);
		if (!(*res)[msg_count]->dn) {
			goto failed;
		}


		(*res)[msg_count]->num_elements = 0;
		(*res)[msg_count]->elements = NULL;
		(*res)[msg_count]->private_data = NULL;

		/* loop over all attributes */
		for (attr=ldap_first_attribute(lldb->ldap, msg, &berptr);
		     attr;
		     attr=ldap_next_attribute(lldb->ldap, msg, berptr)) {
			struct berval **bval;
			bval = ldap_get_values_len(lldb->ldap, msg, attr);

			if (bval) {
				lldb_add_msg_attr(ldb, (*res)[msg_count], attr, bval);
				ldap_value_free_len(bval);
			}					  
			
			ldap_memfree(attr);
		}
		if (berptr) ber_free(berptr, 0);

		msg_count++;
	}

	ldap_msgfree(ldapres);

	return msg_count;

failed:
	if (*res) lldb_search_free(module, *res);
	return -1;
}


/*
  convert a ldb_message structure to a list of LDAPMod structures
  ready for ldap_add() or ldap_modify()
*/
static LDAPMod **lldb_msg_to_mods(struct ldb_context *ldb,
				  const struct ldb_message *msg, int use_flags)
{
	LDAPMod **mods;
	unsigned int i, j;
	int num_mods = 0;

	/* allocate maximum number of elements needed */
	mods = talloc_array_p(ldb, LDAPMod *, msg->num_elements+1);
	if (!mods) {
		errno = ENOMEM;
		return NULL;
	}
	mods[0] = NULL;

	for (i=0;i<msg->num_elements;i++) {
		const struct ldb_message_element *el = &msg->elements[i];

		mods[num_mods] = talloc_p(ldb, LDAPMod);
		if (!mods[num_mods]) {
			goto failed;
		}
		mods[num_mods+1] = NULL;
		mods[num_mods]->mod_op = LDAP_MOD_BVALUES;
		if (use_flags) {
			switch (el->flags & LDB_FLAG_MOD_MASK) {
			case LDB_FLAG_MOD_ADD:
				mods[num_mods]->mod_op |= LDAP_MOD_ADD;
				break;
			case LDB_FLAG_MOD_DELETE:
				mods[num_mods]->mod_op |= LDAP_MOD_DELETE;
				break;
			case LDB_FLAG_MOD_REPLACE:
				mods[num_mods]->mod_op |= LDAP_MOD_REPLACE;
				break;
			}
		}
		mods[num_mods]->mod_type = el->name;
		mods[num_mods]->mod_vals.modv_bvals = talloc_array_p(mods[num_mods], 
								     struct berval *,
								     1+el->num_values);
		if (!mods[num_mods]->mod_vals.modv_bvals) {
			goto failed;
		}

		for (j=0;j<el->num_values;j++) {
			mods[num_mods]->mod_vals.modv_bvals[j] = talloc_p(mods[num_mods]->mod_vals.modv_bvals,
									  struct berval);
			if (!mods[num_mods]->mod_vals.modv_bvals[j]) {
				goto failed;
			}
			mods[num_mods]->mod_vals.modv_bvals[j]->bv_val = el->values[j].data;
			mods[num_mods]->mod_vals.modv_bvals[j]->bv_len = el->values[j].length;
		}
		mods[num_mods]->mod_vals.modv_bvals[j] = NULL;
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
static int lldb_add(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_context *ldb = module->ldb;
	struct lldb_private *lldb = module->private_data;
	LDAPMod **mods;
	int ret = 0;

	/* ignore ltdb specials */
	if (msg->dn[0] == '@') {
		return 0;
	}

	mods = lldb_msg_to_mods(ldb, msg, 0);

	lldb->last_rc = ldap_add_s(lldb->ldap, msg->dn, mods);
	if (lldb->last_rc != LDAP_SUCCESS) {
		ret = -1;
	}

	talloc_free(mods);

	return ret;
}


/*
  modify a record
*/
static int lldb_modify(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_context *ldb = module->ldb;
	struct lldb_private *lldb = module->private_data;
	LDAPMod **mods;
	int ret = 0;

	/* ignore ltdb specials */
	if (msg->dn[0] == '@') {
		return 0;
	}

	mods = lldb_msg_to_mods(ldb, msg, 1);

	lldb->last_rc = ldap_modify_s(lldb->ldap, msg->dn, mods);
	if (lldb->last_rc != LDAP_SUCCESS) {
		ret = -1;
	}

	talloc_free(mods);

	return ret;
}

static int lldb_lock(struct ldb_module *module, const char *lockname)
{
	int ret = 0;

	if (lockname == NULL) {
		return -1;
	}

	/* TODO implement a local locking mechanism here */

	return ret;
}

static int lldb_unlock(struct ldb_module *module, const char *lockname)
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
static const char *lldb_errstring(struct ldb_module *module)
{
	struct lldb_private *lldb = module->private_data;
	return ldap_err2string(lldb->last_rc);
}


static const struct ldb_module_ops lldb_ops = {
	"ldap",
	lldb_close, 
	lldb_search,
	lldb_search_free,
	lldb_add,
	lldb_modify,
	lldb_delete,
	lldb_rename,
	lldb_lock,
	lldb_unlock,
	lldb_errstring
};


static int lldb_destructor(void *p)
{
	struct lldb_private *lldb = p;
	ldap_unbind(lldb->ldap);
	return 0;
}

/*
  connect to the database
*/
struct ldb_context *lldb_connect(const char *url, 
				 unsigned int flags, 
				 const char *options[])
{
	struct ldb_context *ldb = NULL;
	struct lldb_private *lldb = NULL;
	int i, version = 3;

	ldb = talloc_p(NULL, struct ldb_context);
	if (!ldb) {
		errno = ENOMEM;
		goto failed;
	}

	lldb = talloc_p(ldb, struct lldb_private);
	if (!lldb) {
		errno = ENOMEM;
		goto failed;
	}

	lldb->ldap = NULL;
	lldb->options = NULL;

	lldb->last_rc = ldap_initialize(&lldb->ldap, url);
	if (lldb->last_rc != LDAP_SUCCESS) {
		goto failed;
	}

	talloc_set_destructor(lldb, lldb_destructor);

	lldb->last_rc = ldap_set_option(lldb->ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (lldb->last_rc != LDAP_SUCCESS) {
		goto failed;
	}

	ldb->modules = talloc_p(ldb, struct ldb_module);
	if (!ldb->modules) {
		errno = ENOMEM;
		goto failed;
	}
	ldb->modules->ldb = ldb;
	ldb->modules->prev = ldb->modules->next = NULL;
	ldb->modules->private_data = lldb;
	ldb->modules->ops = &lldb_ops;

	if (options) {
		/* take a copy of the options array, so we don't have to rely
		   on the caller keeping it around (it might be dynamic) */
		for (i=0;options[i];i++) ;

		lldb->options = talloc_array_p(lldb, char *, i+1);
		if (!lldb->options) {
			goto failed;
		}
		
		for (i=0;options[i];i++) {
			lldb->options[i+1] = NULL;
			lldb->options[i] = talloc_strdup(lldb->options, options[i]);
			if (!lldb->options[i]) {
				goto failed;
			}
		}
	}

	return ldb;

failed:
	talloc_free(ldb);
	return NULL;
}

