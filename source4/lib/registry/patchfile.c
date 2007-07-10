/* 
   Unix SMB/CIFS implementation.
   Reading .REG files
   
   Copyright (C) Jelmer Vernooij 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/registry/registry.h"
#include "system/filesys.h"

/**
 * @file
 * @brief Registry patch files
 */

#define DEFAULT_IDENT_STRING "SAMBA4 REGISTRY"

static struct reg_diff_key *diff_find_add_key(struct reg_diff *diff, const char *path)
{
	int i;
	
	for (i = 0; diff->numkeys; i++) {
		if (!strcasecmp(diff->keys[i].name, path))
			return &diff->keys[i];
	}

	diff->keys = talloc_realloc(diff, diff->keys, struct reg_diff_key, diff->numkeys+2);
	diff->keys[diff->numkeys].name = talloc_strdup(diff->keys, path);
	diff->keys[diff->numkeys].changetype = REG_DIFF_CHANGE_KEY;
	diff->keys[diff->numkeys].numvalues = 0;
	diff->keys[diff->numkeys].values = NULL;

	diff->numkeys++;
	return NULL;
}

/*
 * Generate difference between two keys
 */
static WERROR reg_generate_diff_key(struct reg_diff *diff, struct registry_key *oldkey, struct registry_key *newkey)
{
	int i;
	struct registry_key *t1, *t2;
	struct registry_value *v1, *v2;
	WERROR error1, error2;
	TALLOC_CTX *mem_ctx = talloc_init("writediff");

	/* Subkeys that were deleted */
	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_subkey_by_index(mem_ctx, oldkey, i, &t1)); i++) {
		error2 = reg_key_get_subkey_by_name(mem_ctx, newkey, t1->name, &t2);

		if (W_ERROR_IS_OK(error2))
			continue;

		if (!W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			DEBUG(0, ("Error occured while getting subkey by name: %d\n", W_ERROR_V(error2)));
			return error2;
		}

		/* newkey didn't have such a subkey, add del diff */
		diff->keys = talloc_realloc(diff, diff->keys, struct reg_diff_key, diff->numkeys+2);
		diff->keys[diff->numkeys].name = talloc_strdup(diff->keys, t1->path);
		diff->keys[diff->numkeys].changetype = REG_DIFF_DEL_KEY;
		diff->numkeys++;
	}

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting subkey by index: %d\n", W_ERROR_V(error1)));
		talloc_free(mem_ctx);
		return error1;
	}

	/* Subkeys that were added */
	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_subkey_by_index(mem_ctx, newkey, i, &t1)); i++) {
		error2 = reg_key_get_subkey_by_name(mem_ctx, oldkey, t1->name, &t2);
			
		if (W_ERROR_IS_OK(error2))
			continue;
		
		if (!W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			DEBUG(0, ("Error occured while getting subkey by name: %d\n", W_ERROR_V(error2)));
			return error2;
		}

		/* oldkey didn't have such a subkey, add add diff */
		diff->keys = talloc_realloc(diff, diff->keys, struct reg_diff_key, diff->numkeys+2);
		diff->keys[diff->numkeys].name = talloc_strdup(diff->keys, t1->path);
		diff->keys[diff->numkeys].changetype = REG_DIFF_CHANGE_KEY;
		diff->keys[diff->numkeys].numvalues = 0;
		diff->keys[diff->numkeys].values = NULL;
		diff->numkeys++;

		reg_generate_diff_key(diff, t1, t2);
	}

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting subkey by index: %d\n", W_ERROR_V(error1)));
		talloc_free(mem_ctx);
		return error1;
	}

	/* Values that were changed */
	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_value_by_index(mem_ctx, newkey, i, &v1)); i++) {
		struct reg_diff_key *thiskey = NULL;
		error2 = reg_key_get_value_by_name(mem_ctx, oldkey, v1->name, &v2);
	
		if(!W_ERROR_IS_OK(error2) && 
		   !W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			DEBUG(0, ("Error occured while getting value by name: %d\n", W_ERROR_V(error2)));
			return error2;
		}

		if (W_ERROR_IS_OK(error2) && data_blob_cmp(&v1->data, &v2->data) == 0)
			continue;

		thiskey = diff_find_add_key(diff, oldkey->path);
		thiskey->values = talloc_realloc(diff, thiskey->values, struct reg_diff_value, thiskey->numvalues+2);
		thiskey->values[thiskey->numvalues].name = talloc_strdup(thiskey->values, v1->name);
		thiskey->values[thiskey->numvalues].type = v2->data_type;
		thiskey->values[thiskey->numvalues].changetype = REG_DIFF_SET_VAL;
		thiskey->values[thiskey->numvalues].data = data_blob_dup_talloc(thiskey->values, &v2->data);
		thiskey->numvalues++;
	}

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting value by index: %d\n", W_ERROR_V(error1)));
		talloc_free(mem_ctx);
		return error1;
	}

	/* Values that were deleted */
	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_value_by_index(mem_ctx, oldkey, i, &v1)); i++) {
		struct reg_diff_key *thiskey = NULL;
		error2 = reg_key_get_value_by_name(mem_ctx, newkey, v1->name, &v2);

		if (W_ERROR_IS_OK(error2))
			continue;

		if (!W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			DEBUG(0, ("Error occured while getting value by name: %d\n", W_ERROR_V(error2)));
			return error2;
		}

		thiskey = diff_find_add_key(diff, oldkey->path);
		thiskey->values = talloc_realloc(diff, thiskey->values, struct reg_diff_value, thiskey->numvalues+2);
		thiskey->values[thiskey->numvalues].name = talloc_strdup(thiskey->values, v1->name);
		thiskey->values[thiskey->numvalues].changetype = REG_DIFF_DEL_VAL;
		thiskey->numvalues++;
	}

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting value by index: %d\n", W_ERROR_V(error1)));
		talloc_free(mem_ctx);
		return error1;
	}

	talloc_free(mem_ctx);
	return WERR_OK;
}

/**
 * Generate diff between two registry contexts 
 */
_PUBLIC_ struct reg_diff *reg_generate_diff(TALLOC_CTX *mem_ctx, struct registry_context *ctx1, struct registry_context *ctx2)
{
	struct reg_diff *diff = talloc_zero(mem_ctx, struct reg_diff);
	int i;
	WERROR error;

	for(i = HKEY_CLASSES_ROOT; i <= HKEY_PERFORMANCE_NLSTEXT; i++) {
		struct registry_key *r1, *r2;
		error = reg_get_predefined_key(ctx1, i, &r1);
		if (!W_ERROR_IS_OK(error)) {
			DEBUG(0, ("Unable to open hive %s for backend 1\n", reg_get_predef_name(i)));
			continue;
		}
		
		error = reg_get_predefined_key(ctx2, i, &r2);
		if (!W_ERROR_IS_OK(error)) {
			DEBUG(0, ("Unable to open hive %s for backend 2\n", reg_get_predef_name(i)));
			continue;
		}

		reg_generate_diff_key(diff, r1, r2);
	}

	return diff;
}

/**
 * Save registry diff
 */
_PUBLIC_ WERROR reg_diff_save(const struct reg_diff *diff, const char *filename)
{
	int xf, i, j;

	if (filename) {
		xf = open(filename, O_CREAT, 0755);
		if (xf == -1) {
			DEBUG(0, ("Unable to open %s\n", filename));
			return WERR_BADFILE;
		}
	} else 
		xf = STDIN_FILENO;

	fdprintf(xf, "%s\n\n", diff->format?diff->format:DEFAULT_IDENT_STRING);

	for (i = 0; i < diff->numkeys; i++) {
		if (diff->keys[i].changetype == REG_DIFF_DEL_KEY) {
			fdprintf(xf, "-%s\n\n",  diff->keys[i].name);
			continue;
		}

		fdprintf(xf, "[%s]\n", diff->keys[i].name);

		for (j = 0; j < diff->keys[i].numvalues; j++) {
			fdprintf(xf, "\"%s\"=", diff->keys[i].values[j].name);
			switch (diff->keys[i].values[j].changetype) {
				case REG_DIFF_DEL_VAL:
					fdprintf(xf, "-\n");
					break;
				case REG_DIFF_SET_VAL:
					fdprintf(xf, "%s:%s\n", 
							 str_regtype(diff->keys[i].values[j].type), 
							 reg_val_data_string(NULL, 
								diff->keys[i].values[j].type, 
								&diff->keys[i].values[j].data));
					break;
			}
		}

		fdprintf(xf, "\n");
	}

	close(xf);

	return WERR_OK;
}

/**
 * Load diff file
 */
_PUBLIC_ struct reg_diff *reg_diff_load(TALLOC_CTX *ctx, const char *fn)
{
	struct reg_diff *diff;
	int fd;
	char *line, *p, *q;
	struct reg_diff_key *curkey = NULL;
	struct reg_diff_value *curval;

	fd = open(fn, O_RDONLY, 0);
	if (fd == -1) {
		DEBUG(0, ("Error opening registry patch file `%s'\n", fn));
		return NULL;
	}

	diff = talloc_zero(ctx, struct reg_diff);
	if (diff == NULL) {
		close(fd);
		return NULL;
	}
	
	diff->format = afdgets(fd, diff, 0);
	if (!diff->format) {
		talloc_free(diff);
		close(fd);
		return NULL;
	}

	while ((line = afdgets(fd, diff, 0))) {
		/* Ignore comments and empty lines */
		if (strlen(line) == 0 || line[0] == ';') {
			curkey = NULL;
			talloc_free(line);
			continue;
		}

		/* Start of key */
		if (line[0] == '[') {
			p = strchr_m(line, ']');
			if (p[strlen(p)-2] != ']') {
				DEBUG(0, ("Malformed line\n"));
				return NULL;
			}
			diff->keys = talloc_realloc(diff, diff->keys, struct reg_diff_key, diff->numkeys+2);
			diff->keys[diff->numkeys].name = talloc_strndup(diff->keys, line+1, strlen(line)-2);
			diff->keys[diff->numkeys].changetype = REG_DIFF_CHANGE_KEY;
			diff->keys[diff->numkeys].numvalues = 0;
			diff->keys[diff->numkeys].values = NULL;
			curkey = &diff->keys[diff->numkeys];
			diff->numkeys++;
			talloc_free(line);
			continue;
		}

		/* Deleting key */
		if (line[0] == '-') {
			diff->keys = talloc_realloc(diff, diff->keys, struct reg_diff_key, diff->numkeys+2);
			diff->keys[diff->numkeys].name = talloc_strdup(diff->keys, line+1);
			diff->keys[diff->numkeys].changetype = REG_DIFF_DEL_KEY;
			diff->numkeys++;
			talloc_free(line);
			continue;
		}

		/* Deleting/Changing value */
		p = strchr_m(line, '=');
		if (p == NULL) {
			DEBUG(0, ("Malformed line\n"));
			talloc_free(line);
			continue;
		}

		*p = '\0'; p++;

		if (curkey == NULL) {
			DEBUG(0, ("Value change without key\n"));
			talloc_free(line);
			continue;
		}

		curkey->values = talloc_realloc(diff->keys, curkey->values, struct reg_diff_value, curkey->numvalues+2);
		curval = &curkey->values[curkey->numvalues];
		curkey->numvalues++;
		curval->name = talloc_strdup(curkey->values, line);

		/* Delete value */
		if (strcmp(p, "-")) {
			curval->changetype = REG_DIFF_DEL_VAL;
			talloc_free(line);
			continue;
		}
		
		q = strchr_m(p, ':');
		if (q) {
			*q = '\0'; 
			q++;
		}

		curval->changetype = REG_DIFF_SET_VAL;
		reg_string_to_val(curkey->values, q?p:"REG_SZ", q?q:p, &curval->type, &curval->data);

		talloc_free(line);
	}

	close(fd);

	return diff;
}

/**
 * Apply diff to a registry context 
 */
_PUBLIC_ BOOL reg_diff_apply (const struct reg_diff *diff, struct registry_context *ctx)
{
	TALLOC_CTX *mem_ctx = talloc_init("apply_cmd_file");
	struct registry_key *tmp = NULL;
	WERROR error;
	int i, j;

	for (i = 0; i < diff->numkeys; i++) {
		if (diff->keys[i].changetype == REG_DIFF_DEL_KEY) {
			error = reg_key_del_abs(ctx, diff->keys[i].name);

			if(!W_ERROR_IS_OK(error)) {
				DEBUG(0, ("Unable to delete key '%s'\n", diff->keys[i].name));
				return False;
		  	}

			continue;
		}

		/* Add / change key */
		error = reg_open_key_abs(mem_ctx, ctx, diff->keys[i].name, &tmp);

		/* If we found it, apply the other bits, else create such a key */
		if (W_ERROR_EQUAL(error, WERR_DEST_NOT_FOUND)) {
			if(!W_ERROR_IS_OK(reg_key_add_abs(mem_ctx, ctx, diff->keys[i].name, 0, NULL, &tmp))) {
				DEBUG(0, ("Error adding new key '%s'\n", diff->keys[i].name));
				return False;
			}
		}

		for (j = 0; j < diff->keys[i].numvalues; j++) {
			if (diff->keys[i].values[j].changetype == REG_DIFF_DEL_VAL) {
				error = reg_del_value(tmp, diff->keys[i].values[j].name);
				if (!W_ERROR_IS_OK(error)) {
					DEBUG(0, ("Error deleting value '%s'\n", diff->keys[i].values[j].name));
					return False;
				}
			
				error = reg_val_set(tmp, diff->keys[i].values[j].name, 
							 diff->keys[i].values[j].type,
							 diff->keys[i].values[j].data);
				if (!W_ERROR_IS_OK(error)) {
					DEBUG(0, ("Error setting value '%s'\n", diff->keys[i].values[j].name));
					return False;
				}	
			}
		}
	}

	return True;
}
