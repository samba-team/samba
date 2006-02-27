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

/* basic module structure */
struct ldb_module {
	struct ldb_module *prev, *next;
	struct ldb_context *ldb;
	void *private_data;
	const struct ldb_module_ops *ops;
};

/* 
   these function pointers define the operations that a ldb module must perform
   they correspond exactly to the ldb_*() interface 
*/
struct ldb_module_ops {
	const char *name;
	int (*request)(struct ldb_module *, struct ldb_request *);
	int (*start_transaction)(struct ldb_module *);
	int (*end_transaction)(struct ldb_module *);
	int (*del_transaction)(struct ldb_module *);
	int (*second_stage_init)(struct ldb_module *);
};


/*
  schema related information needed for matching rules
*/
struct ldb_schema {
	/* attribute handling table */
	unsigned num_attrib_handlers;
	struct ldb_attrib_handler *attrib_handlers;

	/* objectclass information */
	unsigned num_classes;
	struct ldb_subclass {
		char *name;
		char **subclasses;
	} *classes;
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

	int (*async_wait)(struct ldb_async_handle *, enum ldb_async_wait_type);

	/* a backend supplied highestCommittedUSN function */
	uint64_t (*sequence_number)(struct ldb_context *);
};

/* the modules init function */
typedef struct ldb_module *(*ldb_module_init_t)(struct ldb_context *, const char **);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

/*
  simplify out of memory handling
*/
#define ldb_oom(ldb) ldb_debug_set(ldb, LDB_DEBUG_FATAL, "ldb out of memory at %s:%d\n", __FILE__, __LINE__)

/* The following definitions come from lib/ldb/common/ldb.c */
int ldb_second_stage_init(struct ldb_context *ldb);
	
/* The following definitions come from lib/ldb/common/ldb_modules.c  */

int ldb_load_modules(struct ldb_context *ldb, const char *options[]);
int ldb_next_request(struct ldb_module *module, struct ldb_request *request);
int ldb_next_start_trans(struct ldb_module *module);
int ldb_next_end_trans(struct ldb_module *module);
int ldb_next_del_trans(struct ldb_module *module);
int ldb_next_second_stage_init(struct ldb_module *module);

void ldb_set_errstring(struct ldb_context *ldb, char *err_string);
void ldb_reset_err_string(struct ldb_context *ldb);

/* The following definitions come from lib/ldb/common/ldb_debug.c  */
void ldb_debug(struct ldb_context *ldb, enum ldb_debug_level level, const char *fmt, ...) PRINTF_ATTRIBUTE(3, 4);
void ldb_debug_set(struct ldb_context *ldb, enum ldb_debug_level level, 
		   const char *fmt, ...) PRINTF_ATTRIBUTE(3, 4);

/* The following definitions come from lib/ldb/common/ldb_ldif.c  */
int ldb_should_b64_encode(const struct ldb_val *val);

int ltdb_connect(struct ldb_context *ldb, const char *url, 
		 unsigned int flags, 
		 const char *options[]);
int lldb_connect(struct ldb_context *ldb, const char *url, 
		 unsigned int flags, 
		 const char *options[]);
int ildb_connect(struct ldb_context *ldb,
		 const char *url, 
		 unsigned int flags, 
		 const char *options[]);
int lsqlite3_connect(struct ldb_context *ldb,
		     const char *url, 
		     unsigned int flags, 
		     const char *options[]);
struct ldb_module *objectclass_module_init(struct ldb_context *ldb, const char *options[]);
struct ldb_module *operational_module_init(struct ldb_context *ldb, const char *options[]);
struct ldb_module *paged_results_module_init(struct ldb_context *ldb, const char *options[]);
struct ldb_module *rdn_name_module_init(struct ldb_context *ldb, const char *options[]);
struct ldb_module *schema_module_init(struct ldb_context *ldb, const char *options[]);
struct ldb_module *server_sort_module_init(struct ldb_context *ldb, const char *options[]);
struct ldb_module *asq_module_init(struct ldb_context *ldb, const char *options[]);


int ldb_match_msg(struct ldb_context *ldb,
		  struct ldb_message *msg,
		  struct ldb_parse_tree *tree,
		  const struct ldb_dn *base,
		  enum ldb_scope scope);

void ldb_remove_attrib_handler(struct ldb_context *ldb, const char *attrib);
const struct ldb_attrib_handler *ldb_attrib_handler_syntax(struct ldb_context *ldb,
							   const char *syntax);
int ldb_set_attrib_handlers(struct ldb_context *ldb, 
			    const struct ldb_attrib_handler *handlers, 
			    unsigned num_handlers);
int ldb_setup_wellknown_attributes(struct ldb_context *ldb);
int ldb_set_attrib_handler_syntax(struct ldb_context *ldb, 
				  const char *attr, const char *syntax);

/* The following definitions come from lib/ldb/common/ldb_attributes.c  */
const char **ldb_subclass_list(struct ldb_context *ldb, const char *class);
void ldb_subclass_remove(struct ldb_context *ldb, const char *class);
int ldb_subclass_add(struct ldb_context *ldb, const char *class, const char *subclass);

int ldb_handler_copy(struct ldb_context *ldb, void *mem_ctx,
		     const struct ldb_val *in, struct ldb_val *out);
int ldb_comparison_binary(struct ldb_context *ldb, void *mem_ctx,
			  const struct ldb_val *v1, const struct ldb_val *v2);

/* The following definitions come from lib/ldb/common/ldb_controls.c  */
struct ldb_control *get_control_from_list(struct ldb_control **controls, const char *oid);
int save_controls(struct ldb_control *exclude, struct ldb_request *req, struct ldb_control ***saver);
int check_critical_controls(struct ldb_control **controls);

/* The following definitions come from lib/ldb/common/ldb_utf8.c */
char *ldb_casefold_default(void *context, void *mem_ctx, const char *s);
#endif
