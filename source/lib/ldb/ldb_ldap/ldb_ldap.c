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
#include "ldb_ldap/ldb_ldap.h"

#if 0
/*
  we don't need this right now, but will once we add more backend 
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
static int lldb_close(struct ldb_context *ldb)
{
	int i, ret = 0;
	struct lldb_private *lldb = ldb->private;

	if (ldap_unbind(lldb->ldap) != LDAP_SUCCESS) {
		ret = -1;
	}

	if (lldb->options) {
		for (i=0;lldb->options[i];i++) {
			free(lldb->options[i]);
		}
		free(lldb->options);
	}
	free(lldb);
	free(ldb);

	return ret;
}

/*
  delete a record
*/
static int lldb_delete(struct ldb_context *ldb, const char *dn)
{
	struct lldb_private *lldb = ldb->private;
	int ret = 0;
	
	lldb->last_rc = ldap_delete_s(lldb->ldap, dn);
	if (lldb->last_rc != LDAP_SUCCESS) {
		ret = -1;
	}

	return ret;
}

/*
  free a search message
*/
static int lldb_msg_free(struct ldb_context *ldb, struct ldb_message *msg)
{
	int i;
	free(msg->dn);
	for (i=0;i<msg->num_elements;i++) {
		free(msg->elements[i].name);
		if (msg->elements[i].value.data) {
			free(msg->elements[i].value.data);
		}
	}
	if (msg->elements) free(msg->elements);
	free(msg);
	return 0;
}

/*
  free a search result
*/
static int lldb_search_free(struct ldb_context *ldb, struct ldb_message **res)
{
	int i;
	for (i=0;res[i];i++) {
		if (lldb_msg_free(ldb, res[i]) != 0) {
			return -1;
		}
	}
	free(res);
	return 0;
}


/*
  add a single set of ldap message values to a ldb_message
*/
static int lldb_add_msg_attr(struct ldb_message *msg, 
			     const char *attr, struct berval **bval)
{
	int count, i;
	struct ldb_message_element *el;

	count = ldap_count_values_len(bval);

	if (count <= 0) {
		return -1;
	}

	el = realloc_p(msg->elements, struct ldb_message_element, 
		       msg->num_elements + count);
	if (!el) {
		errno = ENOMEM;
		return -1;
	}

	msg->elements = el;

	for (i=0;i<count;i++) {
		msg->elements[msg->num_elements].name = strdup(attr);
		if (!msg->elements[msg->num_elements].name) {
			return -1;
		}
		msg->elements[msg->num_elements].value.data = malloc(bval[i]->bv_len);
		if (!msg->elements[msg->num_elements].value.data) {
			free(msg->elements[msg->num_elements].name);
			return -1;
		}
		memcpy(msg->elements[msg->num_elements].value.data, 
		       bval[i]->bv_val, bval[i]->bv_len);
		msg->elements[msg->num_elements].value.length = bval[i]->bv_len;
		msg->num_elements++;
	}

	return 0;
}

/*
  search for matching records
*/
static int lldb_search(struct ldb_context *ldb, const char *base,
		       enum ldb_scope scope, const char *expression,
		       const char **attrs, struct ldb_message ***res)
{
	struct lldb_private *lldb = ldb->private;
	int count, msg_count;
	LDAPMessage *ldapres, *msg;

	lldb->last_rc = ldap_search_s(lldb->ldap, base, (int)scope, 
				      expression, attrs, 0, &ldapres);
	if (lldb->last_rc != LDAP_SUCCESS) {
		return -1;
	}

	count = ldap_count_entries(lldb->ldap, ldapres);
	if (count == -1 || count == 0) {
		ldap_msgfree(ldapres);
		return count;
	}

	(*res) = malloc_array_p(struct ldb_message *, count+1);
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
			fprintf(stderr,"Too many messages?!\n");
			break;
		}

		(*res)[msg_count] = malloc_p(struct ldb_message);
		if (!(*res)[msg_count]) {
			goto failed;
		}
		(*res)[msg_count+1] = NULL;

		dn = ldap_get_dn(lldb->ldap, msg);
		if (!dn) {
			goto failed;
		}

		(*res)[msg_count]->dn = strdup(dn);
		ldap_memfree(dn);
		if (!(*res)[msg_count]->dn) {
			goto failed;
		}


		(*res)[msg_count]->num_elements = 0;
		(*res)[msg_count]->elements = NULL;
		(*res)[msg_count]->private = NULL;

		/* loop over all attributes */
		for (attr=ldap_first_attribute(lldb->ldap, msg, &berptr);
		     attr;
		     attr=ldap_next_attribute(lldb->ldap, msg, berptr)) {
			struct berval **bval;
			bval = ldap_get_values_len(lldb->ldap, msg, attr);

			if (bval) {
				lldb_add_msg_attr((*res)[msg_count], attr, bval);
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
	if (*res) lldb_search_free(ldb, *res);
	return -1;
}


/*
  free a set of mods from lldb_msg_to_mods()
*/
static void lldb_mods_free(LDAPMod **mods)
{
	int i, j;

	if (!mods) return;

	for (i=0;mods[i];i++) {
		if (mods[i]->mod_vals.modv_bvals) {
			for (j=0;mods[i]->mod_vals.modv_bvals[j];j++) {
				free(mods[i]->mod_vals.modv_bvals[j]);
			}
			free(mods[i]->mod_vals.modv_bvals);
		}
		free(mods[i]);
	}
	free(mods);
}


/*
  convert a ldb_message structure to a list of LDAPMod structures
  ready for ldap_add() or ldap_modify()
*/
static LDAPMod **lldb_msg_to_mods(const struct ldb_message *msg, int use_flags)
{
	LDAPMod **mods;
	int i, num_vals, num_mods = 0;

	/* allocate maximum number of elements needed */
	mods = malloc_array_p(LDAPMod *, msg->num_elements+1);
	if (!mods) {
		errno = ENOMEM;
		return NULL;
	}
	mods[0] = NULL;

	for (i=0;i<msg->num_elements;i++) {

		if (i > 0 && 
		    (!use_flags || 
		     (msg->elements[i].flags == msg->elements[i-1].flags)) &&
		    strcmp(msg->elements[i].name, msg->elements[i-1].name) == 0) {
			struct berval **b;
			/* when attributes are repeated we need to extend the
			   existing bvals array */
			b = realloc_p(mods[num_mods-1]->mod_vals.modv_bvals, 
				      struct berval *, num_vals+2);
			if (!b) {
				goto failed;
			}
			mods[num_mods-1]->mod_vals.modv_bvals = b;
			b[num_vals+1] = NULL;
			b[num_vals] = malloc_p(struct berval);
			if (!b[num_vals]) goto failed;
			b[num_vals]->bv_val = msg->elements[i].value.data;
			b[num_vals]->bv_len = msg->elements[i].value.length;
			num_vals++;
			continue;
		}

		num_vals = 1;

		mods[num_mods] = malloc_p(LDAPMod);
		if (!mods[num_mods]) {
			goto failed;
		}
		mods[num_mods+1] = NULL;
		mods[num_mods]->mod_op = LDAP_MOD_BVALUES;
		if (use_flags) {
			switch (msg->elements[i].flags & LDB_FLAG_MOD_MASK) {
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
		mods[num_mods]->mod_type = msg->elements[i].name;
		mods[num_mods]->mod_vals.modv_bvals = malloc_array_p(struct berval *, 2);
		if (!mods[num_mods]->mod_vals.modv_bvals) {
			goto failed;
		}
		mods[num_mods]->mod_vals.modv_bvals[0] = malloc_p(struct berval);
		if (!mods[num_mods]->mod_vals.modv_bvals[0]) {
			goto failed;
		}
		mods[num_mods]->mod_vals.modv_bvals[0]->bv_val = msg->elements[i].value.data;
		mods[num_mods]->mod_vals.modv_bvals[0]->bv_len = msg->elements[i].value.length;
		mods[num_mods]->mod_vals.modv_bvals[1] = NULL;
		num_mods++;
	}

	return mods;

failed:
	lldb_mods_free(mods);
	return NULL;
}


/*
  add a record
*/
static int lldb_add(struct ldb_context *ldb, const struct ldb_message *msg)
{
	struct lldb_private *lldb = ldb->private;
	LDAPMod **mods;
	int ret = 0;

	mods = lldb_msg_to_mods(msg, 0);

	lldb->last_rc = ldap_add_s(lldb->ldap, msg->dn, mods);
	if (lldb->last_rc != LDAP_SUCCESS) {
		ret = -1;
	}

	lldb_mods_free(mods);

	return ret;
}


/*
  modify a record
*/
static int lldb_modify(struct ldb_context *ldb, const struct ldb_message *msg)
{
	struct lldb_private *lldb = ldb->private;
	LDAPMod **mods;
	int ret = 0;

	mods = lldb_msg_to_mods(msg, 1);

	lldb->last_rc = ldap_modify_s(lldb->ldap, msg->dn, mods);
	if (lldb->last_rc != LDAP_SUCCESS) {
		ret = -1;
	}

	lldb_mods_free(mods);

	return ret;
}


/*
  return extended error information
*/
static const char *lldb_errstring(struct ldb_context *ldb)
{
	struct lldb_private *lldb = ldb->private;
	return ldap_err2string(lldb->last_rc);
}


static const struct ldb_backend_ops lldb_ops = {
	lldb_close, 
	lldb_search,
	lldb_search_free,
	lldb_add,
	lldb_modify,
	lldb_delete,
	lldb_errstring
};


/*
  connect to the database
*/
struct ldb_context *lldb_connect(const char *url, 
				 unsigned int flags, 
				 const char *options[])
{
	struct ldb_context *ldb = NULL;
	struct lldb_private *lldb = NULL;
	int i;

	ldb = malloc_p(struct ldb_context);
	if (!ldb) {
		errno = ENOMEM;
		goto failed;
	}

	lldb = malloc_p(struct lldb_private);
	if (!lldb) {
		free(ldb);
		errno = ENOMEM;
		goto failed;
	}

	lldb->ldap = NULL;
	lldb->options = NULL;

	lldb->last_rc = ldap_initialize(&lldb->ldap, url);
	if (lldb->last_rc != LDAP_SUCCESS) {
		goto failed;
	}

	ldb->ops = &lldb_ops;
	ldb->private = lldb;

	if (options) {
		/* take a copy of the options array, so we don't have to rely
		   on the caller keeping it around (it might be dynamic) */
		for (i=0;options[i];i++) ;

		lldb->options = malloc_array_p(char *, i+1);
		if (!lldb->options) {
			goto failed;
		}
		
		for (i=0;options[i];i++) {
			lldb->options[i+1] = NULL;
			lldb->options[i] = strdup(options[i]);
			if (!lldb->options[i]) {
				goto failed;
			}
		}
	}

	return ldb;

failed:
	if (lldb && lldb->options) {
		for (i=0;lldb->options[i];i++) {
			free(lldb->options[i]);
		}
		free(lldb->options);
	}
	if (lldb && lldb->ldap) {
		ldap_unbind(lldb->ldap);
	}
	if (lldb) free(lldb);
	if (ldb) free(ldb);
	return NULL;
}
