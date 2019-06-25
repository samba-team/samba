/* 
   ldb database library

   Copyright (C) Andrew Tridgell    2004
   Copyright (C) Stefan Metzmacher  2004
   Copyright (C) Simo Sorce         2004-2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb private header
 *
 *  Description: defines internal ldb structures used by the subsystem and modules
 *
 *  Author: Andrew Tridgell
 *  Author: Stefan Metzmacher
 */

#ifndef _LDB_PRIVATE_H_
#define _LDB_PRIVATE_H_ 1

#include "replace.h"
#include "system/filesys.h"
#include "system/time.h"
#include "ldb.h"
#include "ldb_module.h"

struct ldb_context;

struct ldb_module_ops;

struct ldb_backend_ops;

#define LDB_HANDLE_FLAG_DONE_CALLED 1
/* call is from an untrusted source - eg. over ldap:// */
#define LDB_HANDLE_FLAG_UNTRUSTED   2

struct ldb_handle {
	int status;
	enum ldb_state state;
	struct ldb_context *ldb;
	unsigned flags;
	/* flags dedicated to be set by application using ldb */
	uint32_t custom_flags;
	unsigned nesting;

	/* Private event context (if not NULL) */
	struct tevent_context *event_context;

	/* used for debugging */
	struct ldb_request *parent;
	const char *location;
};

/* basic module structure */
struct ldb_module {
	struct ldb_module *prev, *next;
	struct ldb_context *ldb;
	void *private_data;
	const struct ldb_module_ops *ops;
};

/*
  schema related information needed for matching rules
*/
struct ldb_schema {
	void *attribute_handler_override_private;
	ldb_attribute_handler_override_fn_t attribute_handler_override;
	
	/* attribute handling table */
	unsigned num_attributes;
	struct ldb_schema_attribute *attributes;

	unsigned num_dn_extended_syntax;
	struct ldb_dn_extended_syntax *dn_extended_syntax;

	/*
	 * If set, the attribute_handler_override has the details of
	 * what attributes have an index
	 */
	bool index_handler_override;
	bool one_level_indexes;

	const char *GUID_index_attribute;
	const char *GUID_index_dn_component;
};

/*
  every ldb connection is started by establishing a ldb_context
*/
struct ldb_context {
	/* the operations provided by the backend */
	struct ldb_module *modules;

	/* debugging operations */
	struct ldb_debug_ops debug_ops;

	/* extended matching rules */
	struct ldb_extended_match_entry {
		const struct ldb_extended_match_rule *rule;
		struct ldb_extended_match_entry *prev, *next;
	} *extended_match_rules;

	/* custom utf8 functions */
	struct ldb_utf8_fns utf8_fns;

	/* backend specific opaque parameters */
	struct ldb_opaque {
		struct ldb_opaque *next;
		const char *name;
		void *value;
	} *opaque;

	struct ldb_schema schema;

	char *err_string;

	int transaction_active;

	int default_timeout;

	unsigned int flags;

	unsigned int create_perms;

	struct tevent_context *ev_ctx;

	/*
	 * If the backend holds locks, we must not use a global event
	 * context, so this flag will be set and ldb_handle_new() will
	 * build a new event context
	 */
	bool require_private_event_context;

	bool prepare_commit_done;

	char *partial_debug;

	struct poptOption *popt_options;

	/*
	 * The ldb options passed to ldb_connect
	 * A NULL terminated array of zero terminated strings
	 */
	const char **options;
};

/* The following definitions come from lib/ldb/common/ldb.c  */

extern const struct ldb_module_ops ldb_objectclass_module_ops;
extern const struct ldb_module_ops ldb_paged_results_module_ops;
extern const struct ldb_module_ops ldb_rdn_name_module_ops;
extern const struct ldb_module_ops ldb_schema_module_ops;
extern const struct ldb_module_ops ldb_asq_module_ops;
extern const struct ldb_module_ops ldb_server_sort_module_ops;
extern const struct ldb_module_ops ldb_ldap_module_ops;
extern const struct ldb_module_ops ldb_ildap_module_ops;
extern const struct ldb_module_ops ldb_paged_searches_module_ops;
extern const struct ldb_module_ops ldb_tdb_module_ops;
extern const struct ldb_module_ops ldb_skel_module_ops;
extern const struct ldb_module_ops ldb_subtree_rename_module_ops;
extern const struct ldb_module_ops ldb_subtree_delete_module_ops;
extern const struct ldb_module_ops ldb_sqlite3_module_ops;
extern const struct ldb_module_ops ldb_wins_ldb_module_ops;
extern const struct ldb_module_ops ldb_ranged_results_module_ops;

extern const struct ldb_backend_ops ldb_tdb_backend_ops;
extern const struct ldb_backend_ops ldb_sqlite3_backend_ops;
extern const struct ldb_backend_ops ldb_ldap_backend_ops;
extern const struct ldb_backend_ops ldb_ldapi_backend_ops;
extern const struct ldb_backend_ops ldb_ldaps_backend_ops;

int ldb_setup_wellknown_attributes(struct ldb_context *ldb);
/*
  remove attributes with a specified flag (eg LDB_ATTR_FLAG_FROM_DB) for this ldb context

  This is to permit correct reloads
*/
void ldb_schema_attribute_remove_flagged(struct ldb_context *ldb, unsigned int flag);
int ldb_schema_attribute_fill_with_syntax(struct ldb_context *ldb,
					  TALLOC_CTX *mem_ctx,
					  const char *attribute,
					  unsigned flags,
					  const struct ldb_schema_syntax *syntax,
					  struct ldb_schema_attribute *a);

const char **ldb_subclass_list(struct ldb_context *ldb, const char *classname);
void ldb_subclass_remove(struct ldb_context *ldb, const char *classname);
int ldb_subclass_add(struct ldb_context *ldb, const char *classname, const char *subclass);

/* The following definitions come from lib/ldb/common/ldb_utf8.c */
char *ldb_casefold_default(void *context, TALLOC_CTX *mem_ctx, const char *s, size_t n);

void ldb_dump_results(struct ldb_context *ldb, struct ldb_result *result, FILE *f);


/* The following definitions come from lib/ldb/common/ldb_modules.c  */

const char **ldb_modules_list_from_string(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const char *string);
int ldb_load_modules(struct ldb_context *ldb, const char *options[]);

struct ldb_val ldb_binary_decode(TALLOC_CTX *mem_ctx, const char *str);


/* The following definitions come from lib/ldb/common/ldb_options.c  */

const char *ldb_options_find(struct ldb_context *ldb, const char *options[],
			     const char *option_name);
const char **ldb_options_copy(TALLOC_CTX *ctx, const char *options[]);

/* The following definitions come from lib/ldb/common/ldb_ldif.c  */

struct ldif_read_file_state {
	FILE *f;
	size_t line_no;
};

struct ldb_ldif *ldb_ldif_read_file_state(struct ldb_context *ldb, 
					  struct ldif_read_file_state *state);

char *ldb_ldif_write_redacted_trace_string(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, 
					   const struct ldb_ldif *ldif);

/*
 * Get the LDB context in use on an LDB DN.
 *
 * This is helpful to the python LDB code, which may use as part of
 * adding base and child components to an existing DN.
 */
struct ldb_context *ldb_dn_get_ldb_context(struct ldb_dn *dn);

#define LDB_MSG_FIND_COMMON_REMOVE_DUPLICATES 1

/**
  Determine whether any values in an element are also in another element,
  and optionally fix that.

  \param ldb      an ldb context
  \param mem_ctx  a talloc context
  \param el       an element
  \param other_el another element
  \param options  flags controlling the function behaviour

  Without the LDB_MSG_FIND_COMMON_REMOVE_DUPLICATES flag, return
  LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS if the elements share values, and
  LDB_SUCCESS if they don't. That is, determine whether there is an
  intersection without changing anything.

  With the LDB_MSG_FIND_COMMON_REMOVE_DUPLICATES flag, any values in common
  are removed from the first element and LDB_SUCCESS is returned.

  LDB_ERR_OPERATIONS_ERROR indicates an allocation failure or an unknown option.
  LDB_ERR_INAPPROPRIATE_MATCHING means the elements differ in name.
*/

int ldb_msg_find_common_values(struct ldb_context *ldb,
			       TALLOC_CTX *mem_ctx,
			       struct ldb_message_element *el,
			       struct ldb_message_element *other_el,
			       uint32_t options);

/**
   Detect whether an element contains duplicate values

   \param ldb a currently unused ldb_context struct
   \param mem_ctx a talloc context
   \param el the element to search
   \param duplicate will point to a duplicate value if there are duplicates,
   or NULL otherwise.
   \param options is a flags field. All values are reserved.

   \return an ldb error code. LDB_ERR_OPERATIONS_ERROR indicates an allocation
   failure or an unknown option flag. Otherwise LDB_SUCCESS.

   \note This search is case sensitive
*/
int ldb_msg_find_duplicate_val(struct ldb_context *ldb,
			       TALLOC_CTX *mem_ctx,
			       const struct ldb_message_element *el,
			       struct ldb_val **duplicate,
			       uint32_t options);
/**
  Check if a particular message will match the given filter

  \param ldb an ldb context
  \param msg the message to be checked
  \param tree the filter tree to check against
  \param scope the scope to match against
         (to avoid matching special DNs except on a base search)
  \param matched a pointer to a boolean set true if it matches,
         false otherwise

  returns LDB_SUCCESS or an error

  \note this is a recursive function, and does short-circuit evaluation
 */
int ldb_match_message(struct ldb_context *ldb,
		      const struct ldb_message *msg,
		      const struct ldb_parse_tree *tree,
		      enum ldb_scope scope, bool *matched);

#endif
