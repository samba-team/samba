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

struct ldb_context;

struct ldb_module_ops;

struct ldb_backend_ops;

struct ldb_handle {
	int status;
	enum ldb_state state;
	struct ldb_context *ldb;
};

/* basic module structure */
struct ldb_module {
	struct ldb_module *prev, *next;
	struct ldb_context *ldb;
	void *private_data;
	const struct ldb_module_ops *ops;
};

/*
   these function pointers define the operations that a ldb module can intercept
*/
struct ldb_module_ops {
	const char *name;
	int (*init_context) (struct ldb_module *);
	int (*search)(struct ldb_module *, struct ldb_request *); /* search */
	int (*add)(struct ldb_module *, struct ldb_request *); /* add */
	int (*modify)(struct ldb_module *, struct ldb_request *); /* modify */
	int (*del)(struct ldb_module *, struct ldb_request *); /* delete */
	int (*rename)(struct ldb_module *, struct ldb_request *); /* rename */
	int (*request)(struct ldb_module *, struct ldb_request *); /* match any other operation */
	int (*extended)(struct ldb_module *, struct ldb_request *); /* extended operations */
	int (*start_transaction)(struct ldb_module *);
	int (*end_transaction)(struct ldb_module *);
	int (*del_transaction)(struct ldb_module *);
	int (*sequence_number)(struct ldb_module *, struct ldb_request *);
    void *private_data;
};

/*
  schema related information needed for matching rules
*/
struct ldb_schema {
	/* attribute handling table */
	unsigned num_attributes;
	struct ldb_schema_attribute *attributes;

	unsigned num_dn_extended_syntax;
	struct ldb_dn_extended_syntax *dn_extended_syntax;
};

/*
  every ldb connection is started by establishing a ldb_context
*/
struct ldb_context {
	/* the operations provided by the backend */
	struct ldb_module *modules;

	/* debugging operations */
	struct ldb_debug_ops debug_ops;

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

	char *modules_dir;

	struct tevent_context *ev_ctx;
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

/*
  simplify out of memory handling
*/
#define ldb_oom(ldb) ldb_debug_set(ldb, LDB_DEBUG_FATAL, "ldb out of memory at %s:%d\n", __FILE__, __LINE__)

/* The following definitions come from lib/ldb/common/ldb.c  */

int ldb_connect_backend(struct ldb_context *ldb, const char *url, const char *options[],
			struct ldb_module **backend_module);
void ldb_set_default_dns(struct ldb_context *ldb);

/* The following definitions come from lib/ldb/common/ldb_debug.c  */
void ldb_debug(struct ldb_context *ldb, enum ldb_debug_level level, const char *fmt, ...) PRINTF_ATTRIBUTE(3, 4);
void ldb_debug_set(struct ldb_context *ldb, enum ldb_debug_level level, 
		   const char *fmt, ...) PRINTF_ATTRIBUTE(3, 4);

/* The following definitions come from lib/ldb/common/ldb_ldif.c  */
int ldb_should_b64_encode(const struct ldb_val *val);

extern const struct ldb_module_ops ldb_objectclass_module_ops;
extern const struct ldb_module_ops ldb_operational_module_ops;
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

int ldb_match_msg(struct ldb_context *ldb,
		  const struct ldb_message *msg,
		  const struct ldb_parse_tree *tree,
		  struct ldb_dn *base,
		  enum ldb_scope scope);

const struct ldb_schema_syntax *ldb_standard_syntax_by_name(struct ldb_context *ldb,
							    const char *syntax);

/* The following definitions come from lib/ldb/common/ldb_attributes.c  */

int ldb_schema_attribute_add_with_syntax(struct ldb_context *ldb,
					 const char *name,
					 unsigned flags,
					 const struct ldb_schema_syntax *syntax);
int ldb_schema_attribute_add(struct ldb_context *ldb, 
			     const char *name,
			     unsigned flags,
			     const char *syntax);
void ldb_schema_attribute_remove(struct ldb_context *ldb, const char *name);
int ldb_setup_wellknown_attributes(struct ldb_context *ldb);

const char **ldb_subclass_list(struct ldb_context *ldb, const char *classname);
void ldb_subclass_remove(struct ldb_context *ldb, const char *classname);
int ldb_subclass_add(struct ldb_context *ldb, const char *classname, const char *subclass);

int ldb_handler_copy(struct ldb_context *ldb, void *mem_ctx,
		     const struct ldb_val *in, struct ldb_val *out);
int ldb_comparison_binary(struct ldb_context *ldb, void *mem_ctx,
			  const struct ldb_val *v1, const struct ldb_val *v2);

/* The following definitions come from lib/ldb/common/ldb_controls.c  */
struct ldb_control *get_control_from_list(struct ldb_control **controls, const char *oid);
int save_controls(struct ldb_control *exclude, struct ldb_request *req, struct ldb_control ***saver);
int check_critical_controls(struct ldb_control **controls);

/* The following definitions come from lib/ldb/common/ldb_utf8.c */
char *ldb_casefold_default(void *context, void *mem_ctx, const char *s, size_t n);

void ldb_msg_remove_element(struct ldb_message *msg, struct ldb_message_element *el);

int ldb_msg_element_compare_name(struct ldb_message_element *el1, 
				 struct ldb_message_element *el2);
void ldb_dump_results(struct ldb_context *ldb, struct ldb_result *result, FILE *f);

/**
  Obtain current/next database sequence number
*/
int ldb_sequence_number(struct ldb_context *ldb, enum ldb_sequence_type type, uint64_t *seq_num);

#define LDB_SEQ_GLOBAL_SEQUENCE    0x01
#define LDB_SEQ_TIMESTAMP_SEQUENCE 0x02


/* MODULES specific headers -- SSS */

/* The following definitions come from lib/ldb/common/ldb_modules.c  */

const char **ldb_modules_list_from_string(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const char *string);
int ldb_load_modules_list(struct ldb_context *ldb, const char **module_list, struct ldb_module *backend, struct ldb_module **out);
int ldb_load_modules(struct ldb_context *ldb, const char *options[]);
int ldb_init_module_chain(struct ldb_context *ldb, struct ldb_module *module);
int ldb_next_request(struct ldb_module *module, struct ldb_request *request);
int ldb_next_start_trans(struct ldb_module *module);
int ldb_next_end_trans(struct ldb_module *module);
int ldb_next_del_trans(struct ldb_module *module);
int ldb_next_init(struct ldb_module *module);

void ldb_set_errstring(struct ldb_context *ldb, const char *err_string);
void ldb_asprintf_errstring(struct ldb_context *ldb, const char *format, ...) PRINTF_ATTRIBUTE(2,3);
void ldb_reset_err_string(struct ldb_context *ldb);

const char *ldb_default_modules_dir(void);

int ldb_register_module(const struct ldb_module_ops *);

typedef int (*ldb_connect_fn)(struct ldb_context *ldb, const char *url,
			      unsigned int flags, const char *options[],
			      struct ldb_module **module);

struct ldb_backend_ops {
	const char *name;
	ldb_connect_fn connect_fn;
};

const char *ldb_default_modules_dir(void);

int ldb_register_backend(const char *url_prefix, ldb_connect_fn);

struct ldb_handle *ldb_handle_new(TALLOC_CTX *mem_ctx, struct ldb_context *ldb);

int ldb_module_send_entry(struct ldb_request *req,
			  struct ldb_message *msg,
			  struct ldb_control **ctrls);

int ldb_module_send_referral(struct ldb_request *req,
					   char *ref);

int ldb_module_done(struct ldb_request *req,
		    struct ldb_control **ctrls,
		    struct ldb_extended *response,
		    int error);

int ldb_mod_register_control(struct ldb_module *module, const char *oid);


struct ldb_val ldb_binary_decode(void *mem_ctx, const char *str);

#endif
