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

	if (strncmp(url, "tdb:", 4) == 0 ||
	    strchr(url, ':') == NULL) {
		return ltdb_connect(url, flags, options);
	}

#if HAVE_LDAP
	if (strncmp(url, "ldap", 4) == 0) {
		return lldb_connect(url, flags, options);
	}
#endif

	errno = EINVAL;
	return NULL;
}

/*
  close the connection to the database
*/
int ldb_close(struct ldb_context *ldb)
{
	return ldb->ops->close(ldb);
}


/*
  search the database given a LDAP-like search expression

  return the number of records found, or -1 on error
*/
int ldb_search(struct ldb_context *ldb, 
	       const char *base,
	       enum ldb_scope scope,
	       const char *expression,
	       char * const *attrs, struct ldb_message ***res)
{
	return ldb->ops->search(ldb, base, scope, expression, attrs, res);
}

/* 
   free a set of messages returned by ldb_search
*/
int ldb_search_free(struct ldb_context *ldb, struct ldb_message **msgs)
{
	return ldb->ops->search_free(ldb, msgs);
}


/*
  add a record to the database. Will fail if a record with the given class and key
  already exists
*/
int ldb_add(struct ldb_context *ldb, 
	    const struct ldb_message *message)
{
	return ldb->ops->add_record(ldb, message);
}

/*
  modify the specified attributes of a record
*/
int ldb_modify(struct ldb_context *ldb, 
	       const struct ldb_message *message)
{
	return ldb->ops->modify_record(ldb, message);
}


/*
  delete a record from the database
*/
int ldb_delete(struct ldb_context *ldb, const char *dn)
{
	return ldb->ops->delete_record(ldb, dn);
}

/*
  return extended error information 
*/
const char *ldb_errstring(struct ldb_context *ldb)
{
	return ldb->ops->errstring(ldb);
}
