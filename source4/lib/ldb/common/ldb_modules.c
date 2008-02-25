/* 
   ldb database library

   Copyright (C) Simo Sorce  2004

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
 *  Component: ldb modules core
 *
 *  Description: core modules routines
 *
 *  Author: Simo Sorce
 */

#include "ldb_includes.h"

#if (_SAMBA_BUILD_ >= 4)
#include "includes.h"
#endif

#define LDB_MODULE_PREFIX	"modules:"
#define LDB_MODULE_PREFIX_LEN	8

void ldb_set_modules_dir(struct ldb_context *ldb, const char *path)
{
	talloc_free(ldb->modules_dir);
	ldb->modules_dir = talloc_strdup(ldb, path);
}

static char *ldb_modules_strdup_no_spaces(TALLOC_CTX *mem_ctx, const char *string)
{
	int i, len;
	char *trimmed;

	trimmed = talloc_strdup(mem_ctx, string);
	if (!trimmed) {
		return NULL;
	}

	len = strlen(trimmed);
	for (i = 0; trimmed[i] != '\0'; i++) {
		switch (trimmed[i]) {
		case ' ':
		case '\t':
		case '\n':
			memmove(&trimmed[i], &trimmed[i + 1], len -i -1);
			break;
		}
	}

	return trimmed;
}


/* modules are called in inverse order on the stack.
   Lets place them as an admin would think the right order is.
   Modules order is important */
const char **ldb_modules_list_from_string(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const char *string)
{
	char **modules = NULL;
	const char **m;
	char *modstr, *p;
	int i;

	/* spaces not admitted */
	modstr = ldb_modules_strdup_no_spaces(mem_ctx, string);
	if ( ! modstr) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in ldb_modules_strdup_no_spaces()\n");
		return NULL;
	}

	modules = talloc_realloc(mem_ctx, modules, char *, 2);
	if ( ! modules ) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in ldb_modules_list_from_string()\n");
		talloc_free(modstr);
		return NULL;
	}
	talloc_steal(modules, modstr);

	i = 0;
	/* The str*r*chr walks backwards:  This is how we get the inverse order mentioned above */
	while ((p = strrchr(modstr, ',')) != NULL) {
		*p = '\0';
		p++;
		modules[i] = p;

		i++;
		modules = talloc_realloc(mem_ctx, modules, char *, i + 2);
		if ( ! modules ) {
			ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in ldb_modules_list_from_string()\n");
			return NULL;
		}

	}
	modules[i] = modstr;

	modules[i + 1] = NULL;

	m = (const char **)modules;

	return m;
}

static struct ops_list_entry {
	const struct ldb_module_ops *ops;
	struct ops_list_entry *next;	
} *registered_modules = NULL;

#ifndef STATIC_LIBLDB_MODULES

#define STATIC_LIBLDB_MODULES \
	ldb_operational_module_ops,	\
	ldb_rdn_name_module_ops,	\
	ldb_paged_results_module_ops,	\
	ldb_sort_module_ops,		\
	ldb_asq_module_ops, \
	NULL
#endif

const static struct ldb_module_ops *builtin_modules[] = {
	STATIC_LIBLDB_MODULES
};

static const struct ldb_module_ops *ldb_find_module_ops(const char *name)
{
	struct ops_list_entry *e;
	int i;

	for (i = 0; builtin_modules[i]; i++) {
		if (strcmp(builtin_modules[i]->name, name) == 0)
			return builtin_modules[i];
	}
 
	for (e = registered_modules; e; e = e->next) {
 		if (strcmp(e->ops->name, name) == 0) 
			return e->ops;
	}

	return NULL;
}


int ldb_register_module(const struct ldb_module_ops *ops)
{
	struct ops_list_entry *entry = talloc(talloc_autofree_context(), struct ops_list_entry);

	if (ldb_find_module_ops(ops->name) != NULL)
		return -1;

	if (entry == NULL)
		return -1;

	entry->ops = ops;
	entry->next = registered_modules;
	registered_modules = entry;

	return 0;
}

void *ldb_dso_load_symbol(struct ldb_context *ldb, const char *name,
			    const char *symbol)
{
	char *path;
	void *handle;
	void *sym;

	if (ldb->modules_dir == NULL)
		return NULL;

	path = talloc_asprintf(ldb, "%s/%s.%s", ldb->modules_dir, name, 
			       SHLIBEXT);

	ldb_debug(ldb, LDB_DEBUG_TRACE, "trying to load %s from %s\n", name, path);

	handle = dlopen(path, RTLD_NOW);
	if (handle == NULL) {
		ldb_debug(ldb, LDB_DEBUG_WARNING, "unable to load %s from %s: %s\n", name, path, dlerror());
		return NULL;
	}

	sym = (int (*)(void))dlsym(handle, symbol);

	if (sym == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "no symbol `%s' found in %s: %s\n", symbol, path, dlerror());
		return NULL;
	}

	talloc_free(path);

	return sym;
}

int ldb_load_modules_list(struct ldb_context *ldb, const char **module_list, struct ldb_module *backend, struct ldb_module **out)
{
	struct ldb_module *module;
	int i;
	
	module = backend;

	for (i = 0; module_list[i] != NULL; i++) {
		struct ldb_module *current;
		const struct ldb_module_ops *ops;
		
		ops = ldb_find_module_ops(module_list[i]);
		if (ops == NULL) {
			int (*init_fn) (void);

			init_fn = ldb_dso_load_symbol(ldb, module_list[i], 
						      "init_module");
			if (init_fn != NULL && init_fn() == 0) {
				ops = ldb_find_module_ops(module_list[i]);
			}
		}

		if (ops == NULL) {
			char *symbol_name = talloc_asprintf(ldb, "ldb_%s_module_ops", 
												module_list[i]);
			if (symbol_name == NULL) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
			ops = ldb_dso_load_symbol(ldb, module_list[i], symbol_name);
			talloc_free(symbol_name);
		}
		
		if (ops == NULL) {
			ldb_debug(ldb, LDB_DEBUG_WARNING, "WARNING: Module [%s] not found\n", 
				  module_list[i]);
			continue;
		}
		
		current = talloc_zero(ldb, struct ldb_module);
		if (current == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		talloc_set_name(current, "ldb_module: %s", module_list[i]);
		
		current->ldb = ldb;
		current->ops = ops;
		
		DLIST_ADD(module, current);
	}
	*out = module;
	return LDB_SUCCESS;
}

int ldb_init_module_chain(struct ldb_context *ldb, struct ldb_module *module) 
{
	while (module && module->ops->init_context == NULL) 
		module = module->next;

	/* init is different in that it is not an error if modules
	 * do not require initialization */

	if (module) {
		int ret = module->ops->init_context(module);
		if (ret != LDB_SUCCESS) {
			ldb_debug(ldb, LDB_DEBUG_FATAL, "module %s initialization failed\n", module->ops->name);
			return ret;
		}
	}

	return LDB_SUCCESS;
}

int ldb_load_modules(struct ldb_context *ldb, const char *options[])
{
	const char **modules = NULL;
	int i;
	int ret;
	TALLOC_CTX *mem_ctx = talloc_new(ldb);
	if (!mem_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* find out which modules we are requested to activate */

	/* check if we have a custom module list passd as ldb option */
	if (options) {
		for (i = 0; options[i] != NULL; i++) {
			if (strncmp(options[i], LDB_MODULE_PREFIX, LDB_MODULE_PREFIX_LEN) == 0) {
				modules = ldb_modules_list_from_string(ldb, mem_ctx, &options[i][LDB_MODULE_PREFIX_LEN]);
			}
		}
	}

	/* if not overloaded by options and the backend is not ldap try to load the modules list from ldb */
	if ((modules == NULL) && (strcmp("ldap", ldb->modules->ops->name) != 0)) { 
		const char * const attrs[] = { "@LIST" , NULL};
		struct ldb_result *res = NULL;
		struct ldb_dn *mods_dn;

		mods_dn = ldb_dn_new(mem_ctx, ldb, "@MODULES");
		if (mods_dn == NULL) {
			talloc_free(mem_ctx);
			return -1;
		}

		ret = ldb_search_exp_fmt(ldb, mods_dn, &res, mods_dn, LDB_SCOPE_BASE, attrs, "@LIST=*");
		
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			ldb_debug(ldb, LDB_DEBUG_TRACE, "no modules required by the db");
		} else if (ret != LDB_SUCCESS) {
			ldb_debug(ldb, LDB_DEBUG_FATAL, "ldb error (%s) occurred searching for modules, bailing out\n", ldb_errstring(ldb));
			talloc_free(mem_ctx);
			return ret;
		} else {
			const char *module_list;
			if (res->count == 0) {
				ldb_debug(ldb, LDB_DEBUG_TRACE, "no modules required by the db");
			} else if (res->count > 1) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Too many records found (%d), bailing out\n", res->count);
				talloc_free(mem_ctx);
				return -1;
			} else {
				module_list = ldb_msg_find_attr_as_string(res->msgs[0], "@LIST", NULL);
				if (!module_list) {
					ldb_debug(ldb, LDB_DEBUG_TRACE, "no modules required by the db");
				}
				modules = ldb_modules_list_from_string(ldb, mem_ctx,
							       module_list);
			}
		}

		talloc_free(mods_dn);
	}

	if (modules != NULL) {
		ret = ldb_load_modules_list(ldb, modules, ldb->modules, &ldb->modules);
		if (ret != LDB_SUCCESS) {
			talloc_free(mem_ctx);
			return ret;
		}
	} else {
		ldb_debug(ldb, LDB_DEBUG_TRACE, "No modules specified for this database");
	}

	ret = ldb_init_module_chain(ldb, ldb->modules);
	talloc_free(mem_ctx);
	return ret;
}

/*
  by using this we allow ldb modules to only implement the functions they care about,
  which makes writing a module simpler, and makes it more likely to keep working
  when ldb is extended
*/
#define FIND_OP(module, op) do { \
	struct ldb_context *ldb = module->ldb; \
	module = module->next; \
	while (module && module->ops->op == NULL) module = module->next; \
	if (module == NULL) { \
		ldb_asprintf_errstring(ldb, "Unable to find backend operation for " #op ); \
		return LDB_ERR_OPERATIONS_ERROR;	\
	}						\
} while (0)


/*
   helper functions to call the next module in chain
*/

int ldb_next_request(struct ldb_module *module, struct ldb_request *request)
{
	int ret;
	switch (request->operation) {
	case LDB_SEARCH:
		FIND_OP(module, search);
		ret = module->ops->search(module, request);
		break;
	case LDB_ADD:
		FIND_OP(module, add);
		ret = module->ops->add(module, request);
		break;
	case LDB_MODIFY:
		FIND_OP(module, modify);
		ret = module->ops->modify(module, request);
		break;
	case LDB_DELETE:
		FIND_OP(module, del);
		ret = module->ops->del(module, request);
		break;
	case LDB_RENAME:
		FIND_OP(module, rename);
		ret = module->ops->rename(module, request);
		break;
	case LDB_EXTENDED:
		FIND_OP(module, extended);
		ret = module->ops->extended(module, request);
		break;
	case LDB_SEQUENCE_NUMBER:
		FIND_OP(module, sequence_number);
		ret = module->ops->sequence_number(module, request);
		break;
	default:
		FIND_OP(module, request);
		ret = module->ops->request(module, request);
		break;
	}
	if (ret == LDB_SUCCESS) {
		return ret;
	}
	if (!ldb_errstring(module->ldb)) {
		/* Set a default error string, to place the blame somewhere */
		ldb_asprintf_errstring(module->ldb, "error in module %s: %s (%d)", module->ops->name, ldb_strerror(ret), ret);
	}
	return ret;
}

int ldb_next_init(struct ldb_module *module)
{
	module = module->next;

	return ldb_init_module_chain(module->ldb, module);
}

int ldb_next_start_trans(struct ldb_module *module)
{
	FIND_OP(module, start_transaction);
	return module->ops->start_transaction(module);
}

int ldb_next_end_trans(struct ldb_module *module)
{
	FIND_OP(module, end_transaction);
	return module->ops->end_transaction(module);
}

int ldb_next_del_trans(struct ldb_module *module)
{
	FIND_OP(module, del_transaction);
	return module->ops->del_transaction(module);
}
