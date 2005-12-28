
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
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "dlinklist.h"
#include <sys/types.h> 
#include <sys/stat.h> 
#include <unistd.h> 

#ifdef HAVE_DLOPEN_DISABLED
#include <dlfcn.h>
#endif

#define LDB_MODULE_PREFIX	"modules:"
#define LDB_MODULE_PREFIX_LEN	8

static char *talloc_strdup_no_spaces(struct ldb_context *ldb, const char *string)
{
	int i, len;
	char *trimmed;

	trimmed = talloc_strdup(ldb, string);
	if (!trimmed) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in talloc_strdup_trim_spaces()\n");
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
   Modules order is imprtant */
static char **ldb_modules_list_from_string(struct ldb_context *ldb, const char *string)
{
	char **modules = NULL;
	char *modstr, *p;
	int i;

	/* spaces not admitted */
	modstr = talloc_strdup_no_spaces(ldb, string);
	if ( ! modstr) {
		return NULL;
	}

	modules = talloc_realloc(ldb, modules, char *, 2);
	if ( ! modules ) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in ldb_modules_list_from_string()\n");
		talloc_free(modstr);
		return NULL;
	}
	talloc_steal(modules, modstr);

	i = 0;
	while ((p = strrchr(modstr, ',')) != NULL) {
		*p = '\0';
		p++;
		modules[i] = p;

		i++;
		modules = talloc_realloc(ldb, modules, char *, i + 2);
		if ( ! modules ) {
			ldb_debug(ldb, LDB_DEBUG_FATAL, "Out of Memory in ldb_modules_list_from_string()\n");
			return NULL;
		}

	}
	modules[i] = modstr;

	modules[i + 1] = NULL;

	return modules;
}

int ldb_load_modules(struct ldb_context *ldb, const char *options[])
{
	char **modules = NULL;
	int i;
	struct {
		const char *name;
		ldb_module_init_t init;
	} well_known_modules[] = {
		{ "schema", schema_module_init },
		{ "operational", operational_module_init },
		{ "rdn_name", rdn_name_module_init },
#ifdef _SAMBA_BUILD_
		{ "objectguid", objectguid_module_init },
		{ "samldb", samldb_module_init },
		{ "samba3sam", ldb_samba3sam_module_init },
		{ "proxy", proxy_module_init },
		{ "rootdse", rootdse_module_init },
#endif
		{ NULL, NULL }
	};

	/* find out which modules we are requested to activate */

	/* check if we have a custom module list passd as ldb option */
	if (options) {
		for (i = 0; options[i] != NULL; i++) {
			if (strncmp(options[i], LDB_MODULE_PREFIX, LDB_MODULE_PREFIX_LEN) == 0) {
				modules = ldb_modules_list_from_string(ldb, &options[i][LDB_MODULE_PREFIX_LEN]);
			}
		}
	}

	/* if not overloaded by options and the backend is not ldap try to load the modules list form ldb */
	if ((modules == NULL) && (strcmp("ldap", ldb->modules->ops->name) != 0)) { 
		int ret;
		const char * const attrs[] = { "@LIST" , NULL};
		struct ldb_result *res = NULL;
		struct ldb_dn *mods;

		mods = ldb_dn_explode(ldb, "@MODULES");
		if (mods == NULL) {
			return -1;
		}

		ret = ldb_search(ldb, mods, LDB_SCOPE_BASE, "", attrs, &res);
		talloc_free(mods);
		if (ret == LDB_SUCCESS && (res->count == 0 || res->msgs[0]->num_elements == 0)) {
			ldb_debug(ldb, LDB_DEBUG_TRACE, "no modules required by the db\n");
		} else {
			if (ret != LDB_SUCCESS) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "ldb error (%s) occurred searching for modules, bailing out\n", ldb_errstring(ldb));
				return -1;
			}
			if (res->count > 1) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Too many records found (%d), bailing out\n", res->count);
				talloc_free(res);
				return -1;
			}

			modules = ldb_modules_list_from_string(ldb, 
							       (const char *)res->msgs[0]->elements[0].values[0].data);

		}

		talloc_free(res);
	}

	if (modules == NULL) {
		ldb_debug(ldb, LDB_DEBUG_TRACE, "No modules specified for this database\n");
		return 0;
	}

	for (i = 0; modules[i] != NULL; i++) {
		struct ldb_module *current;
		int m;
		for (m=0;well_known_modules[m].name;m++) {
			if (strcmp(modules[i], well_known_modules[m].name) == 0) {
				current = well_known_modules[m].init(ldb, options);
				if (current == NULL) {
					ldb_debug(ldb, LDB_DEBUG_FATAL, "function 'init_module' in %s fails\n", modules[i]);
					return -1;
				}
				DLIST_ADD(ldb->modules, current);
				break;
			}
		}
		if (well_known_modules[m].name == NULL) {
			ldb_debug(ldb, LDB_DEBUG_WARNING, "WARNING: Module [%s] not found\n", 
				  modules[i]);
		}
	}

	talloc_free(modules);
	return 0; 
}

/*
  by using this we allow ldb modules to only implement the functions they care about,
  which makes writing a module simpler, and makes it more likely to keep working
  when ldb is extended
*/
#define FIND_OP(module, op) do { \
	module = module->next; \
	while (module && module->ops->op == NULL) module = module->next; \
	if (module == NULL) return -1; \
} while (0)


/*
   helper functions to call the next module in chain
*/
int ldb_next_request(struct ldb_module *module, struct ldb_request *request)
{
	FIND_OP(module, request);
	return module->ops->request(module, request);
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

void ldb_set_errstring(struct ldb_module *module, char *err_string)
{
	if (module->ldb->err_string) {
		talloc_free(module->ldb->err_string);
	}

	module->ldb->err_string = talloc_steal(module->ldb, err_string);
}

