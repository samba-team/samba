
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
#include "system/filesys.h"

#define LDB_MODULE_PREFIX		"modules"
#define LDB_MODULE_PREFIX_LEN	7
#define LDB_MODULE_SEP		':'

int register_ldb_modules(struct ldb_context *ldb, const char *options[])
{
	void *handle;
	init_ldb_module_function init;
	struct ldb_module *current;
	struct stat st;
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
				} while (p = strchr(q, LDB_MODULE_SEP));
			}
		}
	}

	if (!modules) { /* no modules in the options, look for @MODULES in the db */
		int ret, j, k;
		const char * attrs[] = { "@MODULE" };
		struct ldb_message **msgs;

		ret = ldb_search(ldb, "", LDB_SCOPE_BASE, "dn=@MODULES", (const char * const *)attrs, &msgs);
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

			for (j = 0; j < msgs[0]->num_elements; j++) {
				for (k = 0; k < msgs[0]->elements[j].num_values; k++) {
					pn++;
					modules = ldb_realloc_array(ldb, modules, sizeof(char *), pn);
					if (!modules) {
						ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in register_modules()\n");
						return -1;
					}
					modules[pn - 1] = ldb_strndup(ldb, msgs[0]->elements[j].values[k].data, msgs[0]->elements[j].values[k].length);
					if (!modules[pn - 1]) {
						ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in register_modules()\n");
						return -1;
					}
				}
			}
		}
		ldb_search_free(ldb, msgs);
	}

	if (modules) {

		for (i = 0; i < pn; i++) {
			const char *errstr;

			if (strcmp(modules[i], "timestamps") == 0) {
				current = timestamps_module_init(ldb);
				current->next = ldb->module;
				ldb->module = current;
				continue;
			}

#ifdef HAVE_DLOPEN_DISABLED
			if (stat(modules[i], &st) < 0) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Required module not found, bailing out!\n");
				return -1;
			}

			handle = dlopen(modules[i], RTLD_LAZY);

			if (!handle) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Error loading module %s [%s]\n", modules[i], dlerror());
				return -1;
			}

			init = (init_ldb_module_function)dlsym(handle, "init_module");

			errstr = dlerror();
			if (errstr) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Error trying to resolve symbol 'init_module' in %s [%s]\n", modules[i], errstr);
				return -1;
			}

			current = init(ldb);
			current->next = ldb->module;
			ldb->module = current;

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
	if (!module->next || !module->next->ops->close) {
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
	if (!module->next || !module->next->ops->search) {
		return -1;
	}
	return module->next->ops->search(module->next, base, scope, expression, attrs, res);
}

int ldb_next_search_free(struct ldb_module *module, struct ldb_message **msgs)
{
	if (!module->next || !module->next->ops->search_free) {
		return -1;
	}
	return module->next->ops->search_free(module->next, msgs);
}

int ldb_next_add_record(struct ldb_module *module, const struct ldb_message *message)
{
	if (!module->next || !module->next->ops->add_record) {
		return -1;
	}
	return module->next->ops->add_record(module->next, message);
}

int ldb_next_modify_record(struct ldb_module *module, const struct ldb_message *message)
{
	if (!module->next || !module->next->ops->modify_record) {
		return -1;
	}
	return module->next->ops->modify_record(module->next, message);
}

int ldb_next_delete_record(struct ldb_module *module, const char *dn)
{
	if (!module->next || !module->next->ops->delete_record) {
		return -1;
	}
	return module->next->ops->delete_record(module->next, dn);
}

int ldb_next_rename_record(struct ldb_module *module, const char *olddn, const char *newdn)
{
	if (!module->next || !module->next->ops->rename_record) {
		return -1;
	}
	return module->next->ops->rename_record(module->next, olddn, newdn);
}

const char *ldb_next_errstring(struct ldb_module *module)
{
	if (!module->next || !module->next->ops->errstring) {
		return NULL;
	}
	return module->next->ops->errstring(module->next);
}

void ldb_next_cache_free(struct ldb_module *module)
{
	if (!module->next || !module->next->ops->cache_free) {
		return;
	}
	module->next->ops->cache_free(module->next);
}

