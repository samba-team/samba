
/* 
   ldb database library

   Copyright (C) Simo Sorce  2004

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
 *  Component: ldb modules core
 *
 *  Description: core modules routines
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "dlinklist.h"
#include <sys/types.h> 
#include <sys/stat.h> 
#include <unistd.h> 

#define LDB_MODULE_PREFIX	"modules"
#define LDB_MODULE_PREFIX_LEN	7
#define LDB_MODULE_SEP		':'

int ldb_load_modules(struct ldb_context *ldb, const char *options[])
{
	struct ldb_module *current;
	char **modules;
	char *p, *q;
	int pn, i;

	/* find out which modules we are requested to activate */
	modules = NULL;
	pn = 0;

	if (options) {

		for (i = 0; options[i] != NULL; i++) {

			if (strncmp(options[i], LDB_MODULE_PREFIX, LDB_MODULE_PREFIX_LEN) == 0) {

				p = q = ldb_strdup(ldb, &options[i][LDB_MODULE_PREFIX_LEN]);
				if (*q != ':') {
					ldb_free(ldb, q);
					return -1;
				}
				do {
					*p = '\0';
					q = p + 1;
					pn++;
					modules = ldb_realloc_array(ldb, modules, sizeof(char *), pn);
					if (!modules) {
						ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in register_modules()\n");
						return -1;
					}
					modules[pn - 1] = q;
				} while ((p = strchr(q, LDB_MODULE_SEP)));
			}
		}
	}

	if (!modules && strcmp("ldap", ldb->modules->ops->name)) { /* no modules in the options, look for @MODULES in the db (not for ldap) */
		int ret, j, k;
		const char * const attrs[] = { "@MODULE" , NULL};
		struct ldb_message **msg;

		ret = ldb_search(ldb, "", LDB_SCOPE_BASE, "dn=@MODULES", attrs, &msg);
		if (ret == 0) {
			ldb_debug(ldb, LDB_DEBUG_TRACE, "no modules required by the db\n");
		} else {
			if (ret < 0) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "ldb error (%s) occurred searching for modules, bailing out\n", ldb_errstring(ldb));
				return -1;
			}
			if (ret > 1) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Too many records found, bailing out\n");
				return -1;
			}

			for (j = 0; j < msg[0]->num_elements; j++) {
				for (k = 0; k < msg[0]->elements[j].num_values; k++) {
					pn++;
					modules = ldb_realloc_array(ldb, modules, sizeof(char *), pn);
					if (!modules) {
						ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in register_modules()\n");
						return -1;
					}
					modules[pn - 1] = ldb_strndup(ldb, msg[0]->elements[j].values[k].data, msg[0]->elements[j].values[k].length);
					if (!modules[pn - 1]) {
						ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in register_modules()\n");
						return -1;
					}
				}
			}
		}
		ldb_search_free(ldb, msg);
	}

	if (modules) {

		for (i = 0; i < pn; i++) {

			if (strcmp(modules[i], "timestamps") == 0) {
				current = timestamps_module_init(ldb, options);
				if (!current) {
					ldb_debug(ldb, LDB_DEBUG_FATAL, "function 'init_module' in %s fails\n", modules[i]);
					return -1;
				}
				DLIST_ADD(ldb->modules, current);
				continue;
			}
#if 0
			if (strcmp(modules[i], "schema") == 0) {
				current = schema_module_init(ldb, options);
				if (!current) {
					ldb_debug(ldb, LDB_DEBUG_FATAL, "function 'init_module' in %s fails\n", modules[i]);
					return -1;
				}
				DLIST_ADD(ldb->modules, current);
				continue;
			}
#endif
#ifdef HAVE_DLOPEN_DISABLED
		{
			void *handle;
			ldb_module_init_function init;
			struct stat st;
			const char *errstr;

			if (stat(modules[i], &st) < 0) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Required module [%s] not found, bailing out!\n", modules[i]);
				return -1;
			}

			handle = dlopen(modules[i], RTLD_LAZY);

			if (!handle) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Error loading module %s [%s]\n", modules[i], dlerror());
				return -1;
			}

			init = (ldb_module_init_function)dlsym(handle, "init_module");

			errstr = dlerror();
			if (errstr) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Error trying to resolve symbol 'init_module' in %s [%s]\n", modules[i], errstr);
				return -1;
			}

			current = init(ldb, options);
			if (!current) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "function 'init_module' in %s fails\n", modules[i]);
				return -1;
			}
			DLIST_ADD(ldb->modules, current);
		}
#else
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Required module [%s] not found, bailing out!\n", modules[i]);
		return -1;
#endif
		}
	}

	return 0; 
}

/*
   helper functions to call the next module in chain
*/
int ldb_next_close(struct ldb_module *module)
{
	if (!module->next) {
		return -1;
	}
	return module->next->ops->close(module->next);
}

int ldb_next_search(struct ldb_module *module, 
	       const char *base,
	       enum ldb_scope scope,
	       const char *expression,
	       const char * const *attrs, struct ldb_message ***res)
{
	if (!module->next) {
		return -1;
	}
	return module->next->ops->search(module->next, base, scope, expression, attrs, res);
}

int ldb_next_search_free(struct ldb_module *module, struct ldb_message **msg)
{
	if (!module->next) {
		return -1;
	}
	return module->next->ops->search_free(module->next, msg);
}

int ldb_next_add_record(struct ldb_module *module, const struct ldb_message *message)
{
	if (!module->next) {
		return -1;
	}
	return module->next->ops->add_record(module->next, message);
}

int ldb_next_modify_record(struct ldb_module *module, const struct ldb_message *message)
{
	if (!module->next) {
		return -1;
	}
	return module->next->ops->modify_record(module->next, message);
}

int ldb_next_delete_record(struct ldb_module *module, const char *dn)
{
	if (!module->next) {
		return -1;
	}
	return module->next->ops->delete_record(module->next, dn);
}

int ldb_next_rename_record(struct ldb_module *module, const char *olddn, const char *newdn)
{
	if (!module->next) {
		return -1;
	}
	return module->next->ops->rename_record(module->next, olddn, newdn);
}

const char *ldb_next_errstring(struct ldb_module *module)
{
	if (!module->next) {
		return NULL;
	}
	return module->next->ops->errstring(module->next);
}

void ldb_next_cache_free(struct ldb_module *module)
{
	if (!module->next) {
		return;
	}
	module->next->ops->cache_free(module->next);
}
