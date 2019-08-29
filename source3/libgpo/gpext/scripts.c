/*
 *  Unix SMB/CIFS implementation.
 *  Group Policy Support
 *  Copyright (C) Guenther Deschner 2007
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
#include "../libgpo/gpo_ini.h"
#include "../libgpo/gpo.h"
#include "libgpo/gpo_proto.h"
#include "registry.h"
#include "registry/reg_api.h"
#include "../libcli/registry/util_reg.h"
#include "libgpo/gpext/gpext.h"

#define GP_EXT_NAME "scripts"

#define KEY_GP_SCRIPTS "Software\\Policies\\Microsoft\\Windows\\System\\Scripts"

#define GP_SCRIPTS_INI "Scripts/scripts.ini"

#define GP_SCRIPTS_INI_STARTUP "Startup"
#define GP_SCRIPTS_INI_SHUTDOWN "Shutdown"
#define GP_SCRIPTS_INI_LOGON "Logon"
#define GP_SCRIPTS_INI_LOGOFF "Logoff"

#define GP_SCRIPTS_SECTION_CMDLINE "cmdline"
#define GP_SCRIPTS_SECTION_PARAMETERS "parameters"

#define GP_SCRIPTS_REG_VAL_SCRIPT "Script"
#define GP_SCRIPTS_REG_VAL_PARAMETERS "Parameters"
#define GP_SCRIPTS_REG_VAL_EXECTIME "ExecTime"

NTSTATUS gpext_scripts_init(TALLOC_CTX *mem_ctx);

static TALLOC_CTX *ctx = NULL;

/****************************************************************
****************************************************************/

static NTSTATUS scripts_get_reg_config(TALLOC_CTX *mem_ctx,
				       struct gp_extension_reg_info **reg_info)
{
	NTSTATUS status;
	struct gp_extension_reg_info *info = NULL;

	struct gp_extension_reg_table table[] = {
		{ "ProcessGroupPolicy", REG_SZ, "scripts_process_group_policy" },
		{ "NoGPOListChanges", REG_DWORD, "1" },
		{ "NoSlowLink", REG_DWORD, "1" },
		{ "NotifyLinkTransition", REG_DWORD, "1" },
		{ NULL, REG_NONE, NULL },
	};

	info = talloc_zero(mem_ctx, struct gp_extension_reg_info);
	NT_STATUS_HAVE_NO_MEMORY(info);

	status = gpext_info_add_entry(mem_ctx, GP_EXT_NAME,
				      GP_EXT_GUID_SCRIPTS,
				      table, info);
	NT_STATUS_NOT_OK_RETURN(status);

	*reg_info = info;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS generate_gp_registry_entry(TALLOC_CTX *mem_ctx,
					   const char *key,
					   const char *value,
					   uint32_t data_type,
					   DATA_BLOB *blob,
					   enum gp_reg_action action,
					   struct gp_registry_entry **entry_out)
{
	struct gp_registry_entry *entry = NULL;
	struct registry_value *data = NULL;

	entry = talloc_zero(mem_ctx, struct gp_registry_entry);
	NT_STATUS_HAVE_NO_MEMORY(entry);

	data = talloc_zero(mem_ctx, struct registry_value);
	NT_STATUS_HAVE_NO_MEMORY(data);

	data->type = data_type;
	data->data = *blob;

	entry->key = key;
	entry->data = data;
	entry->action = action;
	entry->value = talloc_strdup(mem_ctx, value);
	NT_STATUS_HAVE_NO_MEMORY(entry->value);

	*entry_out = entry;

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS scripts_parse_ini_section(struct gp_inifile_context *ini_ctx,
					  uint32_t flags,
					  const char *section,
					  struct gp_registry_entry **entries,
					  size_t *num_entries)
{
	NTSTATUS status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	NTSTATUS result;
	int i = 0;

	while (1) {

		const char *key = NULL;
		const char *script = NULL;
		const char *count = NULL;
		const char *parameters = NULL;
		DATA_BLOB blob;
		bool ok;

		count = talloc_asprintf(ini_ctx->mem_ctx, "%d", i);
		NT_STATUS_HAVE_NO_MEMORY(count);

		key = talloc_asprintf(ini_ctx->mem_ctx, "%s:%s%s",
				      section, count,
				      GP_SCRIPTS_SECTION_CMDLINE);
		NT_STATUS_HAVE_NO_MEMORY(key);

		result = gp_inifile_getstring(ini_ctx, key, &script);
		if (!NT_STATUS_IS_OK(result)) {
			break;
		}

		key = talloc_asprintf(ini_ctx->mem_ctx, "%s:%s%s",
				      section, count,
				      GP_SCRIPTS_SECTION_PARAMETERS);
		NT_STATUS_HAVE_NO_MEMORY(key);

		result = gp_inifile_getstring(ini_ctx, key, &parameters);
		if (!NT_STATUS_IS_OK(result)) {
			break;
		}

		{
			struct gp_registry_entry *entry = NULL;

			ok = push_reg_sz(ini_ctx->mem_ctx, &blob, script);
			if (!ok) {
				return NT_STATUS_NO_MEMORY;
			}

			status = generate_gp_registry_entry(ini_ctx->mem_ctx,
							    count,
							    GP_SCRIPTS_REG_VAL_SCRIPT,
							    REG_SZ,
							    &blob,
							    GP_REG_ACTION_ADD_VALUE,
							    &entry);
			NT_STATUS_NOT_OK_RETURN(status);
			if (!add_gp_registry_entry_to_array(ini_ctx->mem_ctx,
							    entry,
							    entries,
							    num_entries)) {
				return NT_STATUS_NO_MEMORY;
			}
		}
		{
			struct gp_registry_entry *entry = NULL;

			ok = push_reg_sz(ini_ctx->mem_ctx, &blob, parameters);
			if (!ok) {
				return NT_STATUS_NO_MEMORY;
			}

			status = generate_gp_registry_entry(ini_ctx->mem_ctx,
							    count,
							    GP_SCRIPTS_REG_VAL_PARAMETERS,
							    REG_SZ,
							    &blob,
							    GP_REG_ACTION_ADD_VALUE,
							    &entry);
			NT_STATUS_NOT_OK_RETURN(status);
			if (!add_gp_registry_entry_to_array(ini_ctx->mem_ctx,
							    entry,
							    entries,
							    num_entries)) {
				return NT_STATUS_NO_MEMORY;
			}
		}
		{
			struct gp_registry_entry *entry = NULL;

			blob = data_blob_talloc_zero(ini_ctx->mem_ctx, 8);

			status = generate_gp_registry_entry(ini_ctx->mem_ctx,
							    count,
							    GP_SCRIPTS_REG_VAL_EXECTIME,
							    REG_QWORD,
							    &blob,
							    GP_REG_ACTION_ADD_VALUE,
							    &entry);
			NT_STATUS_NOT_OK_RETURN(status);
			if (!add_gp_registry_entry_to_array(ini_ctx->mem_ctx,
							    entry,
							    entries,
							    num_entries)) {
				return NT_STATUS_NO_MEMORY;
			}
		}
		status = NT_STATUS_OK;
		i++;
	}

	return status;
}

/****************************************************************
****************************************************************/

static WERROR scripts_store_reg_gpovals(TALLOC_CTX *mem_ctx,
					struct registry_key *key,
					const struct GROUP_POLICY_OBJECT *gpo)
{
	WERROR werr;

	if (!key || !gpo) {
		return WERR_INVALID_PARAMETER;
	}

	werr = gp_store_reg_val_sz(mem_ctx, key, "DisplayName",
		gpo->display_name);
	W_ERROR_NOT_OK_RETURN(werr);

	werr = gp_store_reg_val_sz(mem_ctx, key, "FileSysPath",
		gpo->file_sys_path);
	W_ERROR_NOT_OK_RETURN(werr);

	werr = gp_store_reg_val_sz(mem_ctx, key, "GPO-ID",
		gpo->ds_path);
	W_ERROR_NOT_OK_RETURN(werr);

	werr = gp_store_reg_val_sz(mem_ctx, key, "GPOName",
		gpo->name);
	W_ERROR_NOT_OK_RETURN(werr);

	werr = gp_store_reg_val_sz(mem_ctx, key, "SOM-ID",
		gpo->link);
	W_ERROR_NOT_OK_RETURN(werr);

	return werr;
}

/****************************************************************
****************************************************************/

static WERROR scripts_apply(TALLOC_CTX *mem_ctx,
			    const struct security_token *token,
			    struct registry_key *root_key,
			    uint32_t flags,
			    const char *section,
			    const struct GROUP_POLICY_OBJECT *gpo,
			    struct gp_registry_entry *entries,
			    size_t num_entries)
{
	struct gp_registry_context *reg_ctx = NULL;
	WERROR werr;
	size_t i;
	const char *keystr = NULL;
	int count = 0;

	if (num_entries == 0) {
		return WERR_OK;
	}

#if 0
	if (flags & GPO_INFO_FLAG_MACHINE) {
		struct security_token *tmp_token;

		tmp_token = registry_create_system_token(mem_ctx);
		W_ERROR_HAVE_NO_MEMORY(tmp_token);

		werr = gp_init_reg_ctx(mem_ctx, KEY_HKLM, REG_KEY_WRITE,
				       tmp_token,
				       &reg_ctx);
	} else {
		werr = gp_init_reg_ctx(mem_ctx, KEY_HKCU, REG_KEY_WRITE,
				       token,
				       &reg_ctx);
	}
	W_ERROR_NOT_OK_RETURN(werr);
#endif

	keystr = talloc_asprintf(mem_ctx, "%s\\%s\\%d", KEY_GP_SCRIPTS,
				 section, count++);
	W_ERROR_HAVE_NO_MEMORY(keystr);

	reg_deletekey_recursive(root_key, keystr);

	werr = gp_store_reg_subkey(mem_ctx, keystr,
				   root_key, &root_key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = scripts_store_reg_gpovals(mem_ctx, root_key, gpo);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	for (i=0; i<num_entries; i++) {

		werr = reg_apply_registry_entry(mem_ctx, root_key, reg_ctx,
						&(entries)[i],
						token, flags);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,("failed to apply registry: %s\n",
				win_errstr(werr)));
			goto done;
		}
	}

 done:
	gp_free_reg_ctx(reg_ctx);
	return werr;
}

/****************************************************************
****************************************************************/

static NTSTATUS scripts_process_group_policy(TALLOC_CTX *mem_ctx,
					     uint32_t flags,
					     struct registry_key *root_key,
					     const struct security_token *token,
					     const struct GROUP_POLICY_OBJECT *deleted_gpo_list,
					     const struct GROUP_POLICY_OBJECT *changed_gpo_list)
{
	NTSTATUS status;
	WERROR werr;
	int i = 0;
	char *unix_path = NULL;
	struct gp_inifile_context *ini_ctx = NULL;
	struct gp_registry_entry *entries = NULL;
	size_t num_entries = 0;
	const char *list[] = {
		GP_SCRIPTS_INI_STARTUP,
		GP_SCRIPTS_INI_SHUTDOWN,
		GP_SCRIPTS_INI_LOGON,
		GP_SCRIPTS_INI_LOGOFF
	};
	const struct GROUP_POLICY_OBJECT *gpo;
	char *gpo_cache_path = cache_path(talloc_tos(), GPO_CACHE_DIR);
	if (gpo_cache_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* implementation of the policy callback function, see
	 * http://msdn.microsoft.com/en-us/library/aa373494%28v=vs.85%29.aspx
	 * for details - gd */

	/* for now do not process the list of deleted group policies

	for (gpo = deleted_gpo_list; gpo; gpo = gpo->next) {
	}

	*/

	for (gpo = changed_gpo_list; gpo; gpo = gpo->next) {

		gpext_debug_header(0, "scripts_process_group_policy", flags,
				   gpo, GP_EXT_GUID_SCRIPTS, NULL);

		status = gpo_get_unix_path(mem_ctx, gpo_cache_path,
					   gpo, &unix_path);
		if (!NT_STATUS_IS_OK(status)) {
			goto err_cache_path_free;
		}

		status = gp_inifile_init_context(mem_ctx, flags, unix_path,
						 GP_SCRIPTS_INI, &ini_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto err_cache_path_free;
		}

		for (i = 0; i < ARRAY_SIZE(list); i++) {

			TALLOC_FREE(entries);
			num_entries = 0;

			status = scripts_parse_ini_section(ini_ctx, flags, list[i],
							   &entries, &num_entries);
			if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
				continue;
			}

			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(ini_ctx);
				goto err_cache_path_free;
			}

			dump_reg_entries(flags, "READ", entries, num_entries);

			werr = scripts_apply(ini_ctx->mem_ctx, token, root_key,
					     flags, list[i], gpo, entries, num_entries);
			if (!W_ERROR_IS_OK(werr)) {
				continue; /* FIXME: finally fix storing empty strings and REG_QWORD! */
			}
		}

		TALLOC_FREE(ini_ctx);
	}
	status = NT_STATUS_OK;

err_cache_path_free:
	talloc_free(gpo_cache_path);
	return status;
}

/****************************************************************
****************************************************************/

static NTSTATUS scripts_initialize(TALLOC_CTX *mem_ctx)
{
	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static NTSTATUS scripts_shutdown(void)
{
	NTSTATUS status;

	status = gpext_unregister_gp_extension(GP_EXT_NAME);
	if (NT_STATUS_IS_OK(status)) {
		return status;
	}

	TALLOC_FREE(ctx);

	return NT_STATUS_OK;
}

/****************************************************************
****************************************************************/

static struct gp_extension_methods scripts_methods = {
	.initialize		= scripts_initialize,
	.process_group_policy	= scripts_process_group_policy,
	.get_reg_config		= scripts_get_reg_config,
	.shutdown		= scripts_shutdown
};

/****************************************************************
****************************************************************/

NTSTATUS gpext_scripts_init(TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;

	ctx = talloc_init("gpext_scripts_init");
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	status = gpext_register_gp_extension(ctx, SMB_GPEXT_INTERFACE_VERSION,
					     GP_EXT_NAME, GP_EXT_GUID_SCRIPTS,
					     &scripts_methods);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(ctx);
	}

	return status;
}
