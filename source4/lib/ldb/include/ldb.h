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
 *  Component: ldb header
 *
 *  Description: defines for base ldb API
 *
 *  Author: Andrew Tridgell
 */

#ifndef _LDB_H_
#define _LDB_H_ 1

/*
  major restrictions as compared to normal LDAP:

     - no async calls.
     - each record must have a unique key field
     - the key must be representable as a NULL terminated C string and may not 
       contain a comma or braces

  major restrictions as compared to tdb:

     - no explicit locking calls

*/

/*
  an individual lump of data in a result comes in this format. The
  pointer will usually be to a UTF-8 string if the application is
  sensible, but it can be to anything you like, including binary data
  blobs of arbitrary size.
*/
struct ldb_val {
	unsigned int length;
	void *data;
};

#include "ldb_parse.h"


/* these flags are used in ldd_message_element.flags fields. The
   LDA_FLAGS_MOD_* flags are used in ldap_modify() calls to specify
   whether attributes are being added, deleted or modified */
#define LDB_FLAG_MOD_MASK  0x3
#define LDB_FLAG_MOD_ADD     1
#define LDB_FLAG_MOD_REPLACE 2
#define LDB_FLAG_MOD_DELETE  3


/*
  results are given back as arrays of ldb_message_element
*/
struct ldb_message_element {
	unsigned int flags;
	char *name;
	unsigned int num_values;
	struct ldb_val *values;
};


/*
  a ldb_message represents all or part of a record. It can contain an arbitrary
  number of elements. 
*/
struct ldb_message {
	char *dn;
	unsigned int num_elements;
	struct ldb_message_element *elements;
	void *private_data; /* private to the backend */
};

enum ldb_changetype {
	LDB_CHANGETYPE_NONE=0,
	LDB_CHANGETYPE_ADD,
	LDB_CHANGETYPE_DELETE,
	LDB_CHANGETYPE_MODIFY
};

/*
  a ldif record - from ldif_read
*/
struct ldb_ldif {
	enum ldb_changetype changetype;
	struct ldb_message msg;
};

enum ldb_scope {LDB_SCOPE_DEFAULT=-1, 
		LDB_SCOPE_BASE=0, 
		LDB_SCOPE_ONELEVEL=1,
		LDB_SCOPE_SUBTREE=2};

struct ldb_context;

/*
  the fuction type for the callback used in traversing the database
*/
typedef int (*ldb_traverse_fn)(struct ldb_context *, const struct ldb_message *);


/* 
   these function pointers define the operations that a ldb backend must perform
   they correspond exactly to the ldb_*() interface 
*/
struct ldb_backend_ops {
	int (*close)(struct ldb_context *);
	int (*search)(struct ldb_context *, const char *, enum ldb_scope,
		      const char *, char * const [], struct ldb_message ***);
	int (*search_free)(struct ldb_context *, struct ldb_message **);
	int (*add_record)(struct ldb_context *, const struct ldb_message *);
	int (*modify_record)(struct ldb_context *, const struct ldb_message *);
	int (*delete_record)(struct ldb_context *, const char *);
	const char * (*errstring)(struct ldb_context *);

	/* this is called when the alloc ops changes to ensure we 
	   don't have any old allocated data in the context */
	void (*cache_free)(struct ldb_context *);
};


/*
  the user can optionally supply a allocator function. It is presumed
  it will act like a modern realloc(), with a context ptr to allow
  for pool allocators
*/
struct ldb_alloc_ops {
	void *(*alloc)(void *context, void *ptr, size_t size);
	void *context;
};

/* debugging uses one of the following levels */
enum ldb_debug_level {LDB_DEBUG_FATAL, LDB_DEBUG_ERROR, 
		      LDB_DEBUG_WARNING, LDB_DEBUG_TRACE};

/*
  the user can optionally supply a debug function. The function
  is based on the vfprintf() style of interface, but with the addition
  of a severity level
*/
struct ldb_debug_ops {
	void (*debug)(void *context, enum ldb_debug_level level, 
		      const char *fmt, va_list ap);
	void *context;
};


/*
  every ldb connection is started by establishing a ldb_context
*/
struct ldb_context {
	/* a private pointer for the backend to use */
	void *private_data;

	/* the operations provided by the backend */
	const struct ldb_backend_ops *ops;

	/* memory allocation info */
	struct ldb_alloc_ops alloc_ops;

	/* memory allocation info */
	struct ldb_debug_ops debug_ops;
};


#define LDB_FLG_RDONLY 1

/* 
 connect to a database. The URL can either be one of the following forms
   ldb://path
   ldapi://path

   flags is made up of LDB_FLG_*

   the options are passed uninterpreted to the backend, and are
   backend specific
*/
struct ldb_context *ldb_connect(const char *url, unsigned int flags,
				const char *options[]);

/*
  close the connection to the database
*/
int ldb_close(struct ldb_context *ldb);


/*
  search the database given a LDAP-like search expression

  return the number of records found, or -1 on error
*/
int ldb_search(struct ldb_context *ldb, 
	       const char *base,
	       enum ldb_scope scope,
	       const char *expression,
	       char * const *attrs, struct ldb_message ***res);

/* 
   free a set of messages returned by ldb_search
*/
int ldb_search_free(struct ldb_context *ldb, struct ldb_message **msgs);


/*
  add a record to the database. Will fail if a record with the given class and key
  already exists
*/
int ldb_add(struct ldb_context *ldb, 
	    const struct ldb_message *message);

/*
  modify the specified attributes of a record
*/
int ldb_modify(struct ldb_context *ldb, 
	       const struct ldb_message *message);

/*
  delete a record from the database
*/
int ldb_delete(struct ldb_context *ldb, const char *dn);


/*
  return extended error information from the last call
*/
const char *ldb_errstring(struct ldb_context *ldb);

/*
  casefold a string (should be UTF8, but at the moment it isn't)
*/
char *ldb_casefold(struct ldb_context *ldb, const char *s);

/*
  ldif manipulation functions
*/
int ldif_write(struct ldb_context *ldb,
	       int (*fprintf_fn)(void *, const char *, ...), 
	       void *private_data,
	       const struct ldb_ldif *ldif);
void ldif_read_free(struct ldb_context *ldb, struct ldb_ldif *);
struct ldb_ldif *ldif_read(struct ldb_context *ldb, 
			   int (*fgetc_fn)(void *), void *private_data);
struct ldb_ldif *ldif_read_file(struct ldb_context *ldb, FILE *f);
struct ldb_ldif *ldif_read_string(struct ldb_context *ldb, const char *s);
int ldif_write_file(struct ldb_context *ldb, FILE *f, const struct ldb_ldif *msg);


/* useful functions for ldb_message structure manipulation */

/* find an element within an message */
struct ldb_message_element *ldb_msg_find_element(const struct ldb_message *msg, 
						 const char *attr_name);

/* compare two ldb_val values - return 0 on match */
int ldb_val_equal_exact(const struct ldb_val *v1, const struct ldb_val *v2);

/* find a value within an ldb_message_element */
struct ldb_val *ldb_msg_find_val(const struct ldb_message_element *el, 
				 struct ldb_val *val);

/* add a new empty element to a ldb_message */
int ldb_msg_add_empty(struct ldb_context *ldb,
		      struct ldb_message *msg, const char *attr_name, int flags);

/* add a element to a ldb_message */
int ldb_msg_add(struct ldb_context *ldb, 
		struct ldb_message *msg, 
		const struct ldb_message_element *el, 
		int flags);

/* compare two message elements - return 0 on match */
int ldb_msg_element_compare(struct ldb_message_element *el1, 
			    struct ldb_message_element *el2);

/* find elements in a message and convert to a specific type, with
   a give default value if not found. Assumes that elements are
   single valued */
int ldb_msg_find_int(const struct ldb_message *msg, 
		     const char *attr_name,
		     int default_value);
unsigned int ldb_msg_find_uint(const struct ldb_message *msg, 
			       const char *attr_name,
			       int default_value);
double ldb_msg_find_double(const struct ldb_message *msg, 
			   const char *attr_name,
			   double default_value);
const char *ldb_msg_find_string(const struct ldb_message *msg, 
				const char *attr_name,
				const char *default_value);


/*
  this allows the user to choose their own allocation function
  the allocation function should behave like a modern realloc() 
  function, which means that:
     malloc(size)       == alloc(context, NULL, size)
     free(ptr)          == alloc(context, ptr, 0)
     realloc(ptr, size) == alloc(context, ptr, size)
  The context argument is provided to allow for pool based allocators,
  which often take a context argument
*/
int ldb_set_alloc(struct ldb_context *ldb,
		  void *(*alloc)(void *context, void *ptr, size_t size),
		  void *context);

/*
  this allows the user to set a debug function for error reporting
*/
int ldb_set_debug(struct ldb_context *ldb,
		  void (*debug)(void *context, enum ldb_debug_level level, 
				const char *fmt, va_list ap),
		  void *context);

/* this sets up debug to print messages on stderr */
int ldb_set_debug_stderr(struct ldb_context *ldb);


/* these are used as type safe versions of the ldb allocation functions */
#define ldb_malloc_p(ldb, type) (type *)ldb_malloc(ldb, sizeof(type))
#define ldb_malloc_array_p(ldb, type, count) (type *)ldb_realloc_array(ldb, NULL, sizeof(type), count)
#define ldb_realloc_p(ldb, p, type, count) (type *)ldb_realloc_array(ldb, p, sizeof(type), count)

#endif
