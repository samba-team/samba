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
 *  Component: ldb core API
 *
 *  Description: core API routines interfacing to ldb backends
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"

/* 
 connect to a database. The URL can either be one of the following forms
   ldb://path
   ldapi://path

   flags is made up of LDB_FLG_*

   the options are passed uninterpreted to the backend, and are
   backend specific
*/
struct ldb_context *ldb_connect(const char *url, unsigned int flags,
				const char *options[])
{
	struct ldb_context *ldb_ctx = NULL;

	if (strncmp(url, "tdb:", 4) == 0 ||
	    strchr(url, ':') == NULL) {
		ldb_ctx = ltdb_connect(url, flags, options);
	}

#if HAVE_LDAP
	if (strncmp(url, "ldap", 4) == 0) {
		ldb_ctx = lldb_connect(url, flags, options);
	}
#endif


	if (!ldb_ctx) {
		errno = EINVAL;
		return NULL;
	}

	if (ldb_load_modules(ldb_ctx, options) != 0) {
		ldb_close(ldb_ctx);
		errno = EINVAL;
		return NULL;
	}

	return ldb_ctx;
}

/*
  close the connection to the database
*/
int ldb_close(struct ldb_context *ldb)
{
	return ldb->modules->ops->close(ldb->modules);
}


/*
  search the database given a LDAP-like search expression

  return the number of records found, or -1 on error
*/
int ldb_search(struct ldb_context *ldb, 
	       const char *base,
	       enum ldb_scope scope,
	       const char *expression,
	       const char * const *attrs, struct ldb_message ***res)
{
	return ldb->modules->ops->search(ldb->modules, base, scope, expression, attrs, res);
}

/* 
   free a set of messages returned by ldb_search
*/
int ldb_search_free(struct ldb_context *ldb, struct ldb_message **msgs)
{
	return ldb->modules->ops->search_free(ldb->modules, msgs);
}


/*
  add a record to the database. Will fail if a record with the given class and key
  already exists
*/
int ldb_add(struct ldb_context *ldb, 
	    const struct ldb_message *message)
{
	return ldb->modules->ops->add_record(ldb->modules, message);
}

/*
  modify the specified attributes of a record
*/
int ldb_modify(struct ldb_context *ldb, 
	       const struct ldb_message *message)
{
	return ldb->modules->ops->modify_record(ldb->modules, message);
}


/*
  delete a record from the database
*/
int ldb_delete(struct ldb_context *ldb, const char *dn)
{
	return ldb->modules->ops->delete_record(ldb->modules, dn);
}

/*
  rename a record in the database
*/
int ldb_rename(struct ldb_context *ldb, const char *olddn, const char *newdn)
{
	return ldb->modules->ops->rename_record(ldb->modules, olddn, newdn);
}

/*
  return extended error information 
*/
const char *ldb_errstring(struct ldb_context *ldb)
{
	return ldb->modules->ops->errstring(ldb->modules);
}

