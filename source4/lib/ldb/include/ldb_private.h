/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Stefan Metzmacher  2004

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
 *  Description: defines internal ldb structures used by th esubsystem and modules
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
	int (*close)(struct ldb_module *);
	int (*search)(struct ldb_module *, const char *, enum ldb_scope,
		      const char *, const char * const [], struct ldb_message ***);
	int (*search_free)(struct ldb_module *, struct ldb_message **);
	int (*add_record)(struct ldb_module *, const struct ldb_message *);
	int (*modify_record)(struct ldb_module *, const struct ldb_message *);
	int (*delete_record)(struct ldb_module *, const char *);
	int (*rename_record)(struct ldb_module *, const char *, const char *);
	int (*named_lock)(struct ldb_module *, const char *);
	int (*named_unlock)(struct ldb_module *, const char *);
	const char * (*errstring)(struct ldb_module *);
};

/* the modules init function */
typedef struct ldb_module *(*ldb_module_init_function)(void);

/*
  every ldb connection is started by establishing a ldb_context
*/
struct ldb_context {
	/* the operations provided by the backend */
	struct ldb_module *modules;

	/* debugging operations */
	struct ldb_debug_ops debug_ops;
};

/* The following definitions come from lib/ldb/common/ldb_modules.c  */

int ldb_load_modules(struct ldb_context *ldb, const char *options[]);
int ldb_next_close(struct ldb_module *module);
int ldb_next_search(struct ldb_module *module, 
	       const char *base,
	       enum ldb_scope scope,
	       const char *expression,
	       const char * const *attrs, struct ldb_message ***res);
int ldb_next_search_free(struct ldb_module *module, struct ldb_message **msg);
int ldb_next_add_record(struct ldb_module *module, const struct ldb_message *message);
int ldb_next_modify_record(struct ldb_module *module, const struct ldb_message *message);
int ldb_next_delete_record(struct ldb_module *module, const char *dn);
int ldb_next_rename_record(struct ldb_module *module, const char *olddn, const char *newdn);
int ldb_next_named_lock(struct ldb_module *module, const char *lockname);
int ldb_next_named_unlock(struct ldb_module *module, const char *lockname);
const char *ldb_next_errstring(struct ldb_module *module);

/* The following definitions come from lib/ldb/common/ldb_debug.c  */
void ldb_debug(struct ldb_context *ldb, enum ldb_debug_level level, const char *fmt, ...) PRINTF_ATTRIBUTE(3, 4);

/* The following definitions come from lib/ldb/common/ldb_ldif.c  */
char *ldb_base64_encode(struct ldb_context *ldb, const char *buf, int len);
int ldb_should_b64_encode(const struct ldb_val *val);

struct ldb_context *ltdb_connect(const char *url, 
				 unsigned int flags, 
				 const char *options[]);
struct ldb_context *lldb_connect(const char *url, 
				 unsigned int flags, 
				 const char *options[]);
struct ldb_module *timestamps_module_init(struct ldb_context *ldb, const char *options[]);

const char **ldb_options_parse(const char **options, int *ldbopts, const char *arg);

#endif
