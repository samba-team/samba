
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
		struct ldb_message **msg = NULL;

		ret = ldb_search(ldb, "", LDB_SCOPE_BASE, "dn=@MODULES", attrs, &msg);
		if (ret == 0 || (ret == 1 && msg[0]->num_elements == 0)) {
			ldb_debug(ldb, LDB_DEBUG_TRACE, "no modules required by the db\n");
		} else {
			if (ret < 0) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "ldb error (%s) occurred searching for modules, bailing out\n", ldb_errstring(ldb));
				return -1;
			}
			if (ret > 1) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Too many records found, bailing out\n");
				talloc_free(msg);
				return -1;
			}

			modules = ldb_modules_list_from_string(ldb, msg[0]->elements[0].values[0].data);

		}

		talloc_free(msg);
	}

	if (modules == NULL) {
		ldb_debug(ldb, LDB_DEBUG_TRACE, "No modules specified for this database\n");
		return 0;
	}

	for (i = 0; modules[i] != NULL; i++) {
#ifdef HAVE_DLOPEN_DISABLED
		void *handle;
		ldb_module_init_function init;
		struct stat st;
		char *filename;
		const char *errstr;
#endif
		struct ldb_module *current;

		if (strcmp(modules[i], "schema") == 0) {
			current = schema_module_init(ldb, options);
			if (!current) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "function 'init_module' in %s fails\n", modules[i]);
				return -1;
			}
			DLIST_ADD(ldb->modules, current);
			continue;
		}

		if (strcmp(modules[i], "timestamps") == 0) {
			current = timestamps_module_init(ldb, options);
			if (!current) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "function 'init_module' in %s fails\n", modules[i]);
				return -1;
			}
			DLIST_ADD(ldb->modules, current);
			continue;
		}

#ifdef _SAMBA_BUILD_
		if (strcmp(modules[i], "samldb") == 0) {
			current = samldb_module_init(ldb, options);
			if (!current) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "function 'init_module' in %s fails\n", modules[i]);
				return -1;
			}
			DLIST_ADD(ldb->modules, current);
			continue;
		}
#endif

#ifdef HAVE_DLOPEN_DISABLED
		filename = talloc_asprintf(ldb, "%s.so", modules[i]);
		if (!filename) {
			ldb_debug(ldb, LDB_DEBUG_FATAL, "Talloc failed!\n");
			return -1;
		}

		if (stat(filename, &st) < 0) {
			ldb_debug(ldb, LDB_DEBUG_FATAL, "Required module [%s] not found, bailing out!\n", modules[i]);
			return -1;
		}

		handle = dlopen(filename, RTLD_LAZY);

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
#else
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Required module [%s] not found, bailing out!\n", modules[i]);
		return -1;
#endif
	}

	talloc_free(modules);
	return 0; 
}

/*
   helper functions to call the next module in chain
*/

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

int ldb_next_named_lock(struct ldb_module *module, const char *lockname)
{
	if (!module->next) {
		return -1;
	}
	return module->next->ops->named_lock(module->next, lockname);
}

int ldb_next_named_unlock(struct ldb_module *module, const char *lockname)
{
	if (!module->next) {
		return -1;
	}
	return module->next->ops->named_unlock(module->next, lockname);
}

const char *ldb_next_errstring(struct ldb_module *module)
{
	if (!module->next) {
		return NULL;
	}
	return module->next->ops->errstring(module->next);
}

