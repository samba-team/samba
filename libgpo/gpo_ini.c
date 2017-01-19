/*
 *  Unix SMB/CIFS implementation.
 *  Group Policy Support
 *  Copyright (C) Guenther Deschner 2007
 *  Copyright (C) Wilco Baan Hofman 2009
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "gpo.h"
#include "gpo_ini.h"
#include "system/filesys.h"


static bool change_section(const char *section, void *ctx_ptr)
{
	struct gp_inifile_context *ctx = (struct gp_inifile_context *) ctx_ptr;

	if (ctx->current_section) {
		talloc_free(ctx->current_section);
	}
	ctx->current_section = talloc_strdup(ctx, section);
	if (!ctx->current_section) {
		return false;
	}
	return true;
}

/****************************************************************
****************************************************************/

static bool store_keyval_pair(const char *key, const char *value, void *ctx_ptr)
{
	struct gp_inifile_context *ctx = (struct gp_inifile_context *) ctx_ptr;

	ctx->data = talloc_realloc(ctx, ctx->data, struct keyval_pair *, ctx->keyval_count+1);
	if (!ctx->data) {
		return false;
	}

	ctx->data[ctx->keyval_count] = talloc_zero(ctx, struct keyval_pair);
	if (!ctx->data[ctx->keyval_count]) {
		return false;
	}

	ctx->data[ctx->keyval_count]->key = talloc_asprintf(ctx, "%s:%s", ctx->current_section, key);
	ctx->data[ctx->keyval_count]->val = talloc_strdup(ctx, value ? value : "");

	if (!ctx->data[ctx->keyval_count]->key ||
	    !ctx->data[ctx->keyval_count]->val) {
		return false;
	}

	ctx->keyval_count++;
	return true;
}

/****************************************************************
****************************************************************/

static NTSTATUS convert_file_from_ucs2(TALLOC_CTX *mem_ctx,
				       const char *filename_in,
				       char **filename_out)
{
	int tmp_fd = -1;
	uint8_t *data_in = NULL;
	uint8_t *data_out = NULL;
	char *tmp_name = NULL;
	NTSTATUS status;
	size_t n = 0;
	size_t converted_size;
	mode_t mask;

	if (!filename_out) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	data_in = (uint8_t *)file_load(filename_in, &n, 0, mem_ctx);
	if (!data_in) {
		status = NT_STATUS_NO_SUCH_FILE;
		goto out;
	}

	DEBUG(11,("convert_file_from_ucs2: "
	       "data_in[0]: 0x%x, data_in[1]: 0x%x, data_in[2]: 0x%x\n",
		data_in[0], data_in[1], data_in[2]));

	if ((data_in[0] != 0xff) || (data_in[1] != 0xfe) || (data_in[2] != 0x0d)) {
		*filename_out = NULL;
		status = NT_STATUS_OK;
		goto out;
	}

	tmp_name = talloc_asprintf(mem_ctx, "%s/convert_file_from_ucs2.XXXXXX",
		tmpdir());
	if (!tmp_name) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	mask = umask(S_IRWXO | S_IRWXG);
	tmp_fd = mkstemp(tmp_name);
	umask(mask);
	if (tmp_fd == -1) {
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}

	if (!convert_string_talloc(mem_ctx, CH_UTF16LE, CH_UNIX, data_in, n,
				   (void *)&data_out, &converted_size))
	{
		status = NT_STATUS_INVALID_BUFFER_SIZE;
		goto out;
	}

	DEBUG(11,("convert_file_from_ucs2: "
		 "%s skipping utf16-le BOM\n", tmp_name));

	converted_size -= 3;

	if (write(tmp_fd, data_out + 3, converted_size) != converted_size) {
		status = map_nt_error_from_unix_common(errno);
		goto out;
	}

	*filename_out = tmp_name;

	status = NT_STATUS_OK;

 out:
	if (tmp_fd != -1) {
		close(tmp_fd);
	}

	talloc_free(data_in);
	talloc_free(data_out);

	return status;
}

/****************************************************************
****************************************************************/

NTSTATUS gp_inifile_getstring(struct gp_inifile_context *ctx, const char *key, const char **ret)
{
	int i;

	for (i = 0; i < ctx->keyval_count; i++) {
		if (strcmp(ctx->data[i]->key, key) == 0) {
			if (ret) {
				*ret = ctx->data[i]->val;
			}
			return NT_STATUS_OK;
		}
	}
	return NT_STATUS_NOT_FOUND;
}

/****************************************************************
****************************************************************/

NTSTATUS gp_inifile_getint(struct gp_inifile_context *ctx, const char *key, int *ret)
{
	const char *value;
	NTSTATUS result;

	result = gp_inifile_getstring(ctx,key, &value);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (ret) {
		*ret = (int)strtol(value, NULL, 10);
	}
	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

NTSTATUS gp_inifile_getbool(struct gp_inifile_context *ctx, const char *key, bool *ret)
{
	const char *value;
	NTSTATUS result;

	result = gp_inifile_getstring(ctx,key, &value);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (strequal(value, "Yes") ||
	    strequal(value, "True")) {
		if (ret) {
			*ret = true;
		}
		return NT_STATUS_OK;
	} else if (strequal(value, "No") ||
		   strequal(value, "False")) {
		if (ret) {
			*ret = false;
		}
		return NT_STATUS_OK;
	}

	return NT_STATUS_NOT_FOUND;
}

/****************************************************************
****************************************************************/

NTSTATUS gp_inifile_enum_section(struct gp_inifile_context *ctx,
				 const char *section,
				 size_t *num_ini_keys,
				 const char ***ini_keys,
				 const char ***ini_values)
{
	NTSTATUS status;
	int i;
	size_t num_keys = 0, num_vals = 0;
	const char **keys = NULL;
	const char **values = NULL;

	if (section == NULL || num_ini_keys == NULL ||
	    ini_keys == NULL || ini_values == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i = 0; i < ctx->keyval_count; i++) {

		bool ok;

		/*
		 * section: KEYNAME
		 * KEYNAME:value matches
		 * KEYNAME_OEM:value not
		 */

		if (strlen(section)+1 > strlen(ctx->data[i]->key)) {
			continue;
		}

		if (!strnequal(section, ctx->data[i]->key, strlen(section))) {
			continue;
		}

		if (ctx->data[i]->key[strlen(section)] != ':') {
			continue;
		}

		ok = add_string_to_array(ctx, ctx->data[i]->key, &keys, &num_keys);
		if (!ok) {
			status = NT_STATUS_NO_MEMORY;
			goto failed;
		}

		ok = add_string_to_array(ctx, ctx->data[i]->val, &values, &num_vals);
		if (!ok) {
			status = NT_STATUS_NO_MEMORY;
			goto failed;
		}

		if (num_keys != num_vals) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			goto failed;
		}
	}

	*num_ini_keys = num_keys;
	*ini_keys = keys;
	*ini_values = values;

	return NT_STATUS_OK;

 failed:
	talloc_free(keys);
	talloc_free(values);

	return status;
}


/****************************************************************
****************************************************************/

NTSTATUS gp_inifile_init_context(TALLOC_CTX *mem_ctx,
				 uint32_t flags,
				 const char *unix_path,
				 const char *suffix,
				 struct gp_inifile_context **ctx_ret)
{
	struct gp_inifile_context *ctx = NULL;
	NTSTATUS status;
	int rv;
	char *tmp_filename = NULL;
	const char *ini_filename = NULL;

	if (!unix_path || !ctx_ret) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ctx = talloc_zero(mem_ctx, struct gp_inifile_context);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	status = gp_find_file(mem_ctx, flags, unix_path, suffix,
			      &ini_filename);

	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = convert_file_from_ucs2(mem_ctx, ini_filename,
					&tmp_filename);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	rv = pm_process(tmp_filename != NULL ? tmp_filename : ini_filename,
			change_section, store_keyval_pair, ctx);
	if (!rv) {
		return NT_STATUS_NO_SUCH_FILE;
	}


	ctx->generated_filename = tmp_filename;
	ctx->mem_ctx = mem_ctx;

	*ctx_ret = ctx;

	return NT_STATUS_OK;

 failed:

	DEBUG(1,("gp_inifile_init_context failed: %s\n",
		nt_errstr(status)));

	talloc_free(ctx);

	return status;
}

/****************************************************************
****************************************************************/

NTSTATUS gp_inifile_init_context_direct(TALLOC_CTX *mem_ctx,
					const char *unix_path,
					struct gp_inifile_context **pgp_ctx)
{
	struct gp_inifile_context *gp_ctx = NULL;
	NTSTATUS status;
	bool rv;
	char *tmp_filename = NULL;

	if (unix_path == NULL || pgp_ctx == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	gp_ctx = talloc_zero(mem_ctx, struct gp_inifile_context);
	if (gp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = convert_file_from_ucs2(mem_ctx, unix_path,
					&tmp_filename);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	rv = pm_process_with_flags(tmp_filename != NULL ? tmp_filename : unix_path,
				   true,
				   change_section,
				   store_keyval_pair,
				   gp_ctx);
	if (!rv) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	gp_ctx->generated_filename = tmp_filename;
	gp_ctx->mem_ctx = mem_ctx;

	*pgp_ctx = gp_ctx;

	return NT_STATUS_OK;

 failed:

	DEBUG(1,("gp_inifile_init_context_direct failed: %s\n",
		nt_errstr(status)));

	talloc_free(gp_ctx);

	return status;
}


/****************************************************************
 parse the local gpt.ini file
****************************************************************/

#define GPT_INI_SECTION_GENERAL "General"
#define GPT_INI_PARAMETER_VERSION "Version"
#define GPT_INI_PARAMETER_DISPLAYNAME "displayName"

NTSTATUS parse_gpt_ini(TALLOC_CTX *mem_ctx,
		       const char *filename,
		       uint32_t *version,
		       char **display_name)
{
	NTSTATUS result;
	int rv;
	int v = 0;
	const char *name = NULL;
	struct gp_inifile_context *ctx;

	if (!filename) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ctx = talloc_zero(mem_ctx, struct gp_inifile_context);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	rv = pm_process(filename, change_section, store_keyval_pair, ctx);
	if (!rv) {
		return NT_STATUS_NO_SUCH_FILE;
	}


	result = gp_inifile_getstring(ctx, GPT_INI_SECTION_GENERAL
			":"GPT_INI_PARAMETER_DISPLAYNAME, &name);
	if (!NT_STATUS_IS_OK(result)) {
		/* the default domain policy and the default domain controller
		 * policy never have a displayname in their gpt.ini file */
		DEBUG(10,("parse_gpt_ini: no name in %s\n", filename));
	}

	if (name && display_name) {
		*display_name = talloc_strdup(ctx, name);
		if (*display_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	result = gp_inifile_getint(ctx, GPT_INI_SECTION_GENERAL
			":"GPT_INI_PARAMETER_VERSION, &v);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10,("parse_gpt_ini: no version\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (version) {
		*version = v;
	}

	talloc_free(ctx);

	return NT_STATUS_OK;
}
