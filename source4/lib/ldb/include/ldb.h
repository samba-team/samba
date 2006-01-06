/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Stefan Metzmacher  2004
   Copyright (C) Simo Sorce  2005

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
 *  Author: Stefan Metzmacher
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
     UPDATE: we have transactions now, better than locking --SSS.

*/

/*
  an individual lump of data in a result comes in this format. The
  pointer will usually be to a UTF-8 string if the application is
  sensible, but it can be to anything you like, including binary data
  blobs of arbitrary size.
*/
#ifndef ldb_val
struct ldb_val {
	uint8_t *data;
	size_t length;
};
#endif

/* internal ldb exploded dn structures */
struct ldb_dn_component {
	char *name;
	struct ldb_val value;
};
struct ldb_dn {
	int comp_num;
	struct ldb_dn_component *components;
};

/* these flags are used in ldb_message_element.flags fields. The
   LDA_FLAGS_MOD_* flags are used in ldap_modify() calls to specify
   whether attributes are being added, deleted or modified */
#define LDB_FLAG_MOD_MASK  0x3
#define LDB_FLAG_MOD_ADD     1
#define LDB_FLAG_MOD_REPLACE 2
#define LDB_FLAG_MOD_DELETE  3


/*
  well known object IDs
*/
#define LDB_OID_COMPARATOR_AND  "1.2.840.113556.1.4.803"
#define LDB_OID_COMPARATOR_OR   "1.2.840.113556.1.4.804"

/*
  results are given back as arrays of ldb_message_element
*/
struct ldb_message_element {
	unsigned int flags;
	const char *name;
	unsigned int num_values;
	struct ldb_val *values;
};


/*
  a ldb_message represents all or part of a record. It can contain an arbitrary
  number of elements. 
*/
struct ldb_message {
	struct ldb_dn *dn;
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
	struct ldb_message *msg;
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

#define LDB_FLG_RDONLY 1
#define LDB_FLG_NOSYNC 2

#ifndef PRINTF_ATTRIBUTE
#define PRINTF_ATTRIBUTE(a,b)
#endif

/* structures for ldb_parse_tree handling code */
enum ldb_parse_op { LDB_OP_AND=1, LDB_OP_OR=2, LDB_OP_NOT=3,
		    LDB_OP_EQUALITY=4, LDB_OP_SUBSTRING=5,
		    LDB_OP_GREATER=6, LDB_OP_LESS=7, LDB_OP_PRESENT=8,
		    LDB_OP_APPROX=9, LDB_OP_EXTENDED=10 };

struct ldb_parse_tree {
	enum ldb_parse_op operation;
	union {
		struct {
			struct ldb_parse_tree *child;
		} isnot;
		struct {
			const char *attr;
			struct ldb_val value;
		} equality;
		struct {
			const char *attr;
			int start_with_wildcard;
			int end_with_wildcard;
			struct ldb_val **chunks;
		} substring;
		struct {
			const char *attr;
		} present;
		struct {
			const char *attr;
			struct ldb_val value;
		} comparison;
		struct {
			const char *attr;
			int dnAttributes;
			char *rule_id;
			struct ldb_val value;
		} extended;
		struct {
			unsigned int num_elements;
			struct ldb_parse_tree **elements;
		} list;
	} u;
};

struct ldb_parse_tree *ldb_parse_tree(void *mem_ctx, const char *s);
char *ldb_filter_from_tree(void *mem_ctx, struct ldb_parse_tree *tree);
char *ldb_binary_encode(void *ctx, struct ldb_val val);
char *ldb_binary_encode_string(void *mem_ctx, const char *string);

/*
  functions for controlling attribute handling
*/
typedef int (*ldb_attr_handler_t)(struct ldb_context *, void *mem_ctx, const struct ldb_val *, struct ldb_val *);
typedef int (*ldb_attr_comparison_t)(struct ldb_context *, void *mem_ctx, const struct ldb_val *, const struct ldb_val *);

struct ldb_attrib_handler {
	const char *attr;

	/* LDB_ATTR_FLAG_* */
	unsigned flags;

	/* convert from ldif to binary format */
	ldb_attr_handler_t ldif_read_fn;

	/* convert from binary to ldif format */
	ldb_attr_handler_t ldif_write_fn;
	
	/* canonicalise a value, for use by indexing and dn construction */
	ldb_attr_handler_t canonicalise_fn;

	/* compare two values */
	ldb_attr_comparison_t comparison_fn;
};

#define LDB_ATTR_FLAG_HIDDEN       (1<<0) /* the attribute is not returned by default */
#define LDB_ATTR_FLAG_CONSTRUCTED  (1<<1) /* the attribute is constructed from other attributes */


/* well-known ldap attribute syntaxes - see rfc2252 section 4.3.2 */
#define LDB_SYNTAX_DN                   "1.3.6.1.4.1.1466.115.121.1.12"
#define LDB_SYNTAX_DIRECTORY_STRING     "1.3.6.1.4.1.1466.115.121.1.15"
#define LDB_SYNTAX_INTEGER              "1.3.6.1.4.1.1466.115.121.1.27"
#define LDB_SYNTAX_OCTET_STRING         "1.3.6.1.4.1.1466.115.121.1.40"
#define LDB_SYNTAX_UTC_TIME             "1.3.6.1.4.1.1466.115.121.1.53"
#define LDB_SYNTAX_OBJECTCLASS          "LDB_SYNTAX_OBJECTCLASS"

/* sorting helpers */
typedef int (*ldb_qsort_cmp_fn_t) (const void *, const void *, const void *);

#define LDB_CONTROL_PAGED_RESULTS_OID	"1.2.840.113556.1.4.319"
#define LDB_CONTROL_EXTENDED_DN_OID	"1.2.840.113556.1.4.529"
#define LDB_CONTROL_SERVER_SORT_OID	"1.2.840.113556.1.4.473"
#define LDB_CONTROL_SORT_RESP_OID	"1.2.840.113556.1.4.474"

struct ldb_paged_control {
	int size;
	int cookie_len;
	char *cookie;
};

struct ldb_extended_dn_control {
	int type;
};

struct ldb_server_sort_control {
	char *attributeName;
	char *orderingRule;
	int reverse;
};

struct ldb_sort_resp_control {
	int result;
	char *attr_desc;
};

struct ldb_control {
	const char *oid;
	int critical;
	void *data;
};

struct ldb_credentials;

enum ldb_request_type {
	LDB_REQ_SEARCH,
	LDB_REQ_ADD,
	LDB_REQ_MODIFY,
	LDB_REQ_DELETE,
	LDB_REQ_RENAME,
	LDB_REQ_REGISTER
};

struct ldb_result {
	unsigned int count;
	struct ldb_message **msgs;
	struct ldb_control **controls;
};

struct ldb_search {
	const struct ldb_dn *base;
	enum ldb_scope scope;
	struct ldb_parse_tree *tree;
	const char * const *attrs;
	struct ldb_result *res;
};

struct ldb_add {
	const struct ldb_message *message;
};

struct  ldb_modify {
	const struct ldb_message *message;
};

struct ldb_delete {
	const struct ldb_dn *dn;
};

struct ldb_rename {
	const struct ldb_dn *olddn;
	const struct ldb_dn *newdn;
};

struct ldb_register_control {
	const char *oid;
};

struct ldb_request {

	int operation;

	union {
		struct ldb_search search;
		struct ldb_add    add;
		struct ldb_modify mod;
		struct ldb_delete del;
		struct ldb_rename rename;
		struct ldb_register_control reg;
	} op;

	struct ldb_control **controls;
	struct ldb_credentials *creds;
}; 

int ldb_request(struct ldb_context *ldb, struct ldb_request *request);

/*
  initialise a ldb context
*/
struct ldb_context *ldb_init(void *mem_ctx);

/* 
 connect to a database. The URL can either be one of the following forms
   ldb://path
   ldapi://path

   flags is made up of LDB_FLG_*

   the options are passed uninterpreted to the backend, and are
   backend specific
*/
int ldb_connect(struct ldb_context *ldb, const char *url, unsigned int flags, const char *options[]);

/*
  search the database given a LDAP-like search expression

  return the number of records found, or -1 on error

  use talloc_free to free the ldb_message returned
*/
int ldb_search(struct ldb_context *ldb, 
	       const struct ldb_dn *base,
	       enum ldb_scope scope,
	       const char *expression,
	       const char * const *attrs, struct ldb_result **res);

/*
  like ldb_search() but takes a parse tree
*/
int ldb_search_bytree(struct ldb_context *ldb, 
		      const struct ldb_dn *base,
		      enum ldb_scope scope,
		      struct ldb_parse_tree *tree,
		      const char * const *attrs, struct ldb_result **res);

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
  rename a record in the database
*/
int ldb_rename(struct ldb_context *ldb, const struct ldb_dn *olddn, const struct ldb_dn *newdn);

/*
  delete a record from the database
*/
int ldb_delete(struct ldb_context *ldb, const struct ldb_dn *dn);

/*
  start a transaction
*/
int ldb_transaction_start(struct ldb_context *ldb);

/*
  commit a transaction
*/
int ldb_transaction_commit(struct ldb_context *ldb);

/*
  cancel a transaction
*/
int ldb_transaction_cancel(struct ldb_context *ldb);


/*
  return extended error information from the last call
*/
const char *ldb_errstring(struct ldb_context *ldb);

/*
  casefold a string (should be UTF8, but at the moment it isn't)
*/
char *ldb_casefold(void *mem_ctx, const char *s);
int ldb_caseless_cmp(const char *s1, const char *s2);

/*
  ldif manipulation functions
*/
int ldb_ldif_write(struct ldb_context *ldb,
		   int (*fprintf_fn)(void *, const char *, ...), 
		   void *private_data,
		   const struct ldb_ldif *ldif);
void ldb_ldif_read_free(struct ldb_context *ldb, struct ldb_ldif *);
struct ldb_ldif *ldb_ldif_read(struct ldb_context *ldb, 
			       int (*fgetc_fn)(void *), void *private_data);
struct ldb_ldif *ldb_ldif_read_file(struct ldb_context *ldb, FILE *f);
struct ldb_ldif *ldb_ldif_read_string(struct ldb_context *ldb, const char **s);
int ldb_ldif_write_file(struct ldb_context *ldb, FILE *f, const struct ldb_ldif *msg);
char *ldb_base64_encode(void *mem_ctx, const char *buf, int len);
int ldb_base64_decode(char *s);
int ldb_attrib_add_handlers(struct ldb_context *ldb, 
			    const struct ldb_attrib_handler *handlers, 
			    unsigned num_handlers);

/* The following definitions come from lib/ldb/common/ldb_dn.c  */

int ldb_dn_is_special(const struct ldb_dn *dn);
int ldb_dn_check_special(const struct ldb_dn *dn, const char *check);
char *ldb_dn_escape_value(void *mem_ctx, struct ldb_val value);
struct ldb_dn *ldb_dn_new(void *mem_ctx);
struct ldb_dn *ldb_dn_explode(void *mem_ctx, const char *dn);
struct ldb_dn *ldb_dn_explode_or_special(void *mem_ctx, const char *dn);
char *ldb_dn_linearize(void *mem_ctx, const struct ldb_dn *edn);
char *ldb_dn_linearize_casefold(struct ldb_context *ldb, const struct ldb_dn *edn);
int ldb_dn_compare_base(struct ldb_context *ldb, const struct ldb_dn *base, const struct ldb_dn *dn);
int ldb_dn_compare(struct ldb_context *ldb, const struct ldb_dn *edn0, const struct ldb_dn *edn1);
struct ldb_dn *ldb_dn_casefold(struct ldb_context *ldb, const struct ldb_dn *edn);
struct ldb_dn *ldb_dn_explode_casefold(struct ldb_context *ldb, const char *dn);
struct ldb_dn *ldb_dn_copy_partial(void *mem_ctx, const struct ldb_dn *dn, int num_el);
struct ldb_dn *ldb_dn_copy(void *mem_ctx, const struct ldb_dn *dn);
struct ldb_dn *ldb_dn_get_parent(void *mem_ctx, const struct ldb_dn *dn);
struct ldb_dn_component *ldb_dn_build_component(void *mem_ctx, const char *attr,
							       const char *val);
struct ldb_dn *ldb_dn_build_child(void *mem_ctx, const char *attr,
						 const char * value,
						 const struct ldb_dn *base);
struct ldb_dn *ldb_dn_make_child(void *mem_ctx,
				 const struct ldb_dn_component *component,
				 const struct ldb_dn *base);
struct ldb_dn *ldb_dn_compose(void *mem_ctx, const struct ldb_dn *dn1, const struct ldb_dn *dn2);
struct ldb_dn *ldb_dn_string_compose(void *mem_ctx, const struct ldb_dn *base, const char *child_fmt, ...) PRINTF_ATTRIBUTE(3,4);
struct ldb_dn_component *ldb_dn_get_rdn(void *mem_ctx, const struct ldb_dn *dn);

/* useful functions for ldb_message structure manipulation */
int ldb_dn_cmp(struct ldb_context *ldb, const char *dn1, const char *dn2);
int ldb_attr_cmp(const char *attr1, const char *attr2);
int ldb_attr_dn(const char *attr);
char *ldb_dn_escape_value(void *mem_ctx, struct ldb_val value);

/* create an empty message */
struct ldb_message *ldb_msg_new(void *mem_ctx);

/* find an element within an message */
struct ldb_message_element *ldb_msg_find_element(const struct ldb_message *msg, 
						 const char *attr_name);

/* compare two ldb_val values - return 0 on match */
int ldb_val_equal_exact(const struct ldb_val *v1, const struct ldb_val *v2);

/* find a value within an ldb_message_element */
struct ldb_val *ldb_msg_find_val(const struct ldb_message_element *el, 
				 struct ldb_val *val);

/* add a new empty element to a ldb_message */
int ldb_msg_add_empty(struct ldb_message *msg, const char *attr_name, int flags);

/* add a element to a ldb_message */
int ldb_msg_add(struct ldb_message *msg, 
		const struct ldb_message_element *el, 
		int flags);
int ldb_msg_add_value(struct ldb_message *msg, 
		      const char *attr_name,
		      const struct ldb_val *val);
int ldb_msg_add_string(struct ldb_message *msg, 
		       const char *attr_name, const char *str);
int ldb_msg_add_fmt(struct ldb_message *msg, 
		    const char *attr_name, const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);

/* compare two message elements - return 0 on match */
int ldb_msg_element_compare(struct ldb_message_element *el1, 
			    struct ldb_message_element *el2);

/* find elements in a message and convert to a specific type, with
   a give default value if not found. Assumes that elements are
   single valued */
const struct ldb_val *ldb_msg_find_ldb_val(const struct ldb_message *msg, const char *attr_name);
int ldb_msg_find_int(const struct ldb_message *msg, 
		     const char *attr_name,
		     int default_value);
unsigned int ldb_msg_find_uint(const struct ldb_message *msg, 
			       const char *attr_name,
			       unsigned int default_value);
int64_t ldb_msg_find_int64(const struct ldb_message *msg, 
			   const char *attr_name,
			   int64_t default_value);
uint64_t ldb_msg_find_uint64(const struct ldb_message *msg, 
			     const char *attr_name,
			     uint64_t default_value);
double ldb_msg_find_double(const struct ldb_message *msg, 
			   const char *attr_name,
			   double default_value);
const char *ldb_msg_find_string(const struct ldb_message *msg, 
				const char *attr_name,
				const char *default_value);

void ldb_msg_sort_elements(struct ldb_message *msg);

struct ldb_message *ldb_msg_copy_shallow(void *mem_ctx, 
					 const struct ldb_message *msg);
struct ldb_message *ldb_msg_copy(void *mem_ctx, 
				 const struct ldb_message *msg);

struct ldb_message *ldb_msg_canonicalize(struct ldb_context *ldb, 
					 const struct ldb_message *msg);


struct ldb_message *ldb_msg_diff(struct ldb_context *ldb, 
				 struct ldb_message *msg1,
				 struct ldb_message *msg2);

int ldb_msg_sanity_check(const struct ldb_message *msg);

struct ldb_val ldb_val_dup(void *mem_ctx, const struct ldb_val *v);

/*
  this allows the user to set a debug function for error reporting
*/
int ldb_set_debug(struct ldb_context *ldb,
		  void (*debug)(void *context, enum ldb_debug_level level, 
				const char *fmt, va_list ap),
		  void *context);

/* this sets up debug to print messages on stderr */
int ldb_set_debug_stderr(struct ldb_context *ldb);

/* control backend specific opaque values */
int ldb_set_opaque(struct ldb_context *ldb, const char *name, void *value);
void *ldb_get_opaque(struct ldb_context *ldb, const char *name);

const struct ldb_attrib_handler *ldb_attrib_handler(struct ldb_context *ldb,
						    const char *attrib);


const char **ldb_attr_list_copy(void *mem_ctx, const char * const *attrs);
int ldb_attr_in_list(const char * const *attrs, const char *attr);


void ldb_parse_tree_attr_replace(struct ldb_parse_tree *tree, 
				 const char *attr, 
				 const char *replace);

int ldb_msg_rename_attr(struct ldb_message *msg, const char *attr, const char *replace);
int ldb_msg_copy_attr(struct ldb_message *msg, const char *attr, const char *replace);
void ldb_msg_remove_attr(struct ldb_message *msg, const char *attr);

char *ldb_timestring(void *mem_ctx, time_t t);
time_t ldb_string_to_time(const char *s);

char *ldb_dn_canonical_string(void *mem_ctx, const struct ldb_dn *dn);
char *ldb_dn_canonical_ex_string(void *mem_ctx, const struct ldb_dn *dn);


void ldb_qsort (void *const pbase, size_t total_elems, size_t size, void *opaque, ldb_qsort_cmp_fn_t cmp);
#endif
