/*
 *  Samba Unix/Linux SMB client library
 *  Distributed SMB/CIFS Server Management Utility
 *  Local configuration interface
 *  Copyright (C) Vicentiu Ciorbaru 2011
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

/*
 * This is an interface to Samba's configuration.
 *
 * This tool supports local as well as remote interaction via rpc
 * with the configuration stored in the registry.
 */


#include "includes.h"
#include "utils/net.h"
#include "utils/net_conf_util.h"
#include "rpc_client/cli_pipe.h"
#include "../librpc/gen_ndr/ndr_samr_c.h"
#include "rpc_client/init_samr.h"
#include "../librpc/gen_ndr/ndr_winreg_c.h"
#include "../libcli/registry/util_reg.h"
#include "rpc_client/cli_winreg.h"
#include "lib/smbconf/smbconf.h"
#include "lib/smbconf/smbconf_init.h"
#include "lib/smbconf/smbconf_reg.h"
#include "lib/param/loadparm.h"



/* internal functions */
/**********************************************************
 *
 * usage functions
 *
 **********************************************************/
const char confpath[100] = "Software\\Samba\\smbconf";

static int rpc_conf_list_usage(struct net_context *c, int argc,
			       const char **argv)
{
	d_printf("%s net rpc conf list\n", _("Usage:"));
	return -1;
}

static int rpc_conf_listshares_usage(struct net_context *c, int argc,
			             const char **argv)
{
	d_printf("%s net rpc conf listshares\n", _("Usage:"));
	return -1;
}

static int rpc_conf_delshare_usage(struct net_context *c, int argc,
				   const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _("net rpc conf delshare <sharename>\n"));
	return -1;
}

static int rpc_conf_addshare_usage(struct net_context *c, int argc,
				   const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net rpc conf addshare <sharename> <path> "
		   "[writeable={y|N} [guest_ok={y|N} [<comment>]]]\n"
		   "\t<sharename>      the new share name.\n"
		   "\t<path>           the path on the filesystem to export.\n"
		   "\twriteable={y|N}  set \"writeable to \"yes\" or "
		   "\"no\" (default) on this share.\n"
		   "\tguest_ok={y|N}   set \"guest ok\" to \"yes\" or "
		   "\"no\" (default)   on this share.\n"
		   "\t<comment>        optional comment for the new share.\n"));
	return -1;

}

static int rpc_conf_import_usage(struct net_context *c, int argc,
				 const char**argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net rpc conf import [--test|-T] <filename> "
		   "[<servicename>]\n"
		   "\t[--test|-T]    testmode - do not act, just print "
			"what would be done\n"
		   "\t<servicename>  only import service <servicename>, "
			"ignore the rest\n"));
	return -1;
}

static int rpc_conf_showshare_usage(struct net_context *c, int argc,
				    const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _("net rpc conf showshare <sharename>\n"));
	return -1;
}

static int rpc_conf_drop_usage(struct net_context *c, int argc,
			       const char **argv)
{
	d_printf("%s\nnet rpc conf drop\n", _("Usage:"));
	return -1;
}

static int rpc_conf_getparm_usage(struct net_context *c, int argc,
			       const char **argv)
{
	d_printf("%s\nnet rpc conf getparm <sharename> <parameter>\n",
			_("Usage:"));
	return -1;
}

static int rpc_conf_setparm_usage(struct net_context *c, int argc,
				  const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net rpc conf setparm <section> <param> <value>\n"));
	return -1;
}

static int rpc_conf_delparm_usage(struct net_context *c, int argc,
				const char **argv)
{
	d_printf("%s\nnet rpc conf delparm <sharename> <parameter>\n",
			_("Usage:"));
	return -1;
}

static int rpc_conf_getincludes_usage(struct net_context *c, int argc,
				const char **argv)
{
	d_printf("%s\nnet rpc conf getincludes <sharename>\n",
			_("Usage:"));
	return -1;
}

static int rpc_conf_setincludes_usage(struct net_context *c, int argc,
				const char **argv)
{
	d_printf("%s\nnet rpc conf setincludes <sharename> [<filename>]*\n",
			_("Usage:"));
	return -1;
}

static int rpc_conf_delincludes_usage(struct net_context *c, int argc,
				const char **argv)
{
	d_printf("%s\nnet rpc conf delincludes <sharename>\n",
			_("Usage:"));
	return -1;
}

/**********************************************************
 *
 * helper functions
 *
 **********************************************************/

/*
 * The function deletes a registry value with the name 'value' from the share
 * with the name 'share_name'. 'parent_hnd' is the handle for the smbconf key.
 */
static NTSTATUS rpc_conf_del_value(TALLOC_CTX *mem_ctx,
				   struct dcerpc_binding_handle *b,
				   struct policy_handle *parent_hnd,
				   const char *share_name,
				   const char *value,
				   WERROR *werr)
{

	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR result = WERR_OK;
	WERROR _werr;

	struct winreg_String keyname, valuename;
	struct policy_handle child_hnd;

	ZERO_STRUCT(child_hnd);
	ZERO_STRUCT(keyname);
	ZERO_STRUCT(valuename);

	keyname.name = share_name;
	valuename.name = value;

	status = dcerpc_winreg_OpenKey(b, frame, parent_hnd, keyname, 0,
				       REG_KEY_WRITE, &child_hnd, &result);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("Failed to open key '%s': %s\n"),
				keyname.name, nt_errstr(status));
		goto error;
	}

	if (!(W_ERROR_IS_OK(result))) {
		d_fprintf(stderr, _("Failed to open key '%s': %s\n"),
				keyname.name, win_errstr(result));
		goto error;
	}

	status = dcerpc_winreg_DeleteValue(b,
			                   frame,
					   &child_hnd,
					   valuename,
					   &result);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("Failed to delete value %s\n"),
				nt_errstr(status));
		goto error;
	}

	if (!(W_ERROR_IS_OK(result))) {
		if (W_ERROR_EQUAL(result, WERR_BADFILE)){
			result = WERR_OK;
			goto error;
		}

		d_fprintf(stderr, _("Failed to delete value  %s\n"),
				win_errstr(result));
		goto error;
	}

error:
	*werr = result;

	dcerpc_winreg_CloseKey(b, frame, &child_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;;

}

/*
 * The function sets a share in the registry with the parameters
 * held in the smbconf_service struct
 */
static NTSTATUS rpc_conf_set_share(TALLOC_CTX *mem_ctx,
				   struct dcerpc_binding_handle *b,
				   struct policy_handle *parent_hnd,
				   struct smbconf_service *service,
				   WERROR *werr)
{
	TALLOC_CTX *frame = talloc_stackframe();

	NTSTATUS status = NT_STATUS_OK;
	WERROR result = WERR_OK;
	WERROR _werr;
	enum winreg_CreateAction action;
	uint32_t i, j;

	const char **includes;

	struct winreg_String wkey, wkeyclass;
	struct policy_handle share_hnd;

	ZERO_STRUCT(share_hnd);
	ZERO_STRUCT(wkey);
	ZERO_STRUCT(wkeyclass);

	wkey.name = service->name;
	wkeyclass.name = "";
	action = REG_ACTION_NONE;

	status = dcerpc_winreg_CreateKey(b,
					 frame,
					 parent_hnd,
					 wkey,
					 wkeyclass,
					 0,
					 REG_KEY_ALL,
					 NULL,
					 &share_hnd,
					 &action,
					 &result);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("winreg_CreateKey: Could not create smbconf key\n");
		goto error;
	}

	if (!W_ERROR_IS_OK(result)) {
		d_printf("winreg_CreateKey: Could not create smbconf key\n");
		goto error;
	}

	for (i = 0; i < service->num_params; i++) {
		if (strequal(service->param_names[i], "include") == 0)
		{

			status = dcerpc_winreg_set_sz(frame, b, &share_hnd,
						      service->param_names[i],
						      service->param_values[i],
						      &result);

			if (!(NT_STATUS_IS_OK(status))) {
				d_fprintf(stderr,
					  "ERROR: Share: '%s'\n"
					  "Could not set parameter '%s'"
					  " with value %s\n %s\n",
					  service->name,
					  service->param_names[i],
					  service->param_values[i],
					  nt_errstr(status));
				goto error;
			}

			if (!(W_ERROR_IS_OK(result))) {
				d_fprintf(stderr,
					  "ERROR: Share: '%s'\n"
					  "Could not set parameter '%s'"
					  " with value %s\n %s\n",
					  service->name,
					  service->param_names[i],
					  service->param_values[i],
					  win_errstr(result));
				goto error;
			}
		} else {

			includes = talloc_zero_array(frame,
						     const char *,
						     service->num_params + 1);
			if (includes == NULL) {
				result = WERR_NOMEM;
				d_fprintf(stderr, "ERROR: out of memory\n");
				goto error;
			}

			for (j = i; j < service->num_params; j++) {

				includes[j - i] = talloc_strdup(
							frame,
							service->param_values[j]);

				if (includes[j-i] == NULL) {
					result = WERR_NOMEM;
					d_fprintf(stderr, "ERROR: out of memory\n");
					goto error;
				}
			}

			status = dcerpc_winreg_set_multi_sz(frame, b, &share_hnd,
						"includes",
						includes,
						&result);

			if (!(NT_STATUS_IS_OK(status))) {
				d_fprintf(stderr, "ERROR: Share: '%s'\n"
						"Could not set includes\n %s\n",
						service->name,
						nt_errstr(status));
				goto error;
			}

			if (!(W_ERROR_IS_OK(result))) {
				d_fprintf(stderr, "ERROR: Share: '%s'\n"
						"Could not set includes\n %s\n",
						service->name,
						win_errstr(result));
				goto error;
			}

			i = service->num_params;
		}
	}

error:
	/* in case of error, should it delete the created key? */
	if (!(W_ERROR_IS_OK(result))) {
		status =  werror_to_ntstatus(result);

	}

	dcerpc_winreg_CloseKey(b, frame, &share_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;

}

/*
 * The function opens the registry database and retrieves
 * as a smbconf_service struct the share with the name
 * 'share_name'
 */
static NTSTATUS rpc_conf_get_share(TALLOC_CTX *mem_ctx,
				   struct dcerpc_binding_handle *b,
				   struct policy_handle *parent_hnd,
				   const char *share_name,
				   struct smbconf_service *share,
				   WERROR *werr)
{
	TALLOC_CTX *frame = talloc_stackframe();

	NTSTATUS status = NT_STATUS_OK;
	WERROR result = WERR_OK;
	WERROR _werr;
	struct policy_handle child_hnd;
	int32_t includes_cnt, includes_idx = -1;
	uint32_t num_vals, i, param_cnt = 0;
	const char **val_names;
	enum winreg_Type *types;
	DATA_BLOB *data;
	struct winreg_String key = { 0, };
	const char **multi_s = NULL;
	const char *s = NULL;
	struct smbconf_service tmp_share;

	ZERO_STRUCT(tmp_share);

	key.name = share_name;
	status = dcerpc_winreg_OpenKey(b, frame, parent_hnd, key, 0,
			       REG_KEY_READ, &child_hnd, &result);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("Failed to open subkey: %s\n"),
				nt_errstr(status));
		goto error;
	}
	if (!(W_ERROR_IS_OK(result))) {
		d_fprintf(stderr, _("Failed to open subkey: %s\n"),
				win_errstr(result));
		goto error;
	}
	/* get all the info from the share key */
	status = dcerpc_winreg_enumvals(frame,
			b,
			&child_hnd,
			&num_vals,
			&val_names,
			&types,
			&data,
			&result);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("Failed to enumerate values: %s\n"),
				nt_errstr(status));
		goto error;
	}
	if (!(W_ERROR_IS_OK(result))) {
		d_fprintf(stderr, _("Failed to enumerate values: %s\n"),
				win_errstr(result));
		goto error;
	}
	/* check for includes */
	for (i = 0; i < num_vals; i++) {
		if (strcmp(val_names[i], "includes") == 0){
			if (!pull_reg_multi_sz(frame,
					       &data[i],
					       &multi_s))
			{
				result = WERR_NOMEM;
				d_fprintf(stderr,
					  _("Failed to enumerate values: %s\n"),
					  win_errstr(result));
				goto error;
			}
			includes_idx = i;
		}
	}
	/* count the number of includes */
	includes_cnt = 0;
	if (includes_idx != -1) {
		for (includes_cnt = 0;
		     multi_s[includes_cnt] != NULL;
		     includes_cnt ++);
	}
	/* place the name of the share in the smbconf_service struct */
	tmp_share.name = talloc_strdup(frame, share_name);
	if (tmp_share.name == NULL) {
		result = WERR_NOMEM;
		d_fprintf(stderr, _("Failed to create share: %s\n"),
				win_errstr(result));
		goto error;
	}
	/* place the number of parameters in the smbconf_service struct */
	tmp_share.num_params = num_vals;
	if (includes_idx != -1) {
		tmp_share.num_params = num_vals + includes_cnt - 1;
	}
	/* allocate memory for the param_names and param_values lists */
	tmp_share.param_names = talloc_zero_array(frame, char *, tmp_share.num_params);
	if (tmp_share.param_names == NULL) {
		result = WERR_NOMEM;
		d_fprintf(stderr, _("Failed to create share: %s\n"),
				win_errstr(result));
		goto error;
	}
	tmp_share.param_values = talloc_zero_array(frame, char *, tmp_share.num_params);
	if (tmp_share.param_values == NULL) {
		result = WERR_NOMEM;
		d_fprintf(stderr, _("Failed to create share: %s\n"),
				win_errstr(result));
		goto error;
	}
	/* place all params except includes */
	for (i = 0; i < num_vals; i++) {
		if (strcmp(val_names[i], "includes") != 0) {
			if (!pull_reg_sz(frame, &data[i], &s)) {
				result = WERR_NOMEM;
				d_fprintf(stderr,
					  _("Failed to enumerate values: %s\n"),
					  win_errstr(result));
				goto error;
			}
			/* place param_names */
			tmp_share.param_names[param_cnt] = talloc_strdup(frame, val_names[i]);
			if (tmp_share.param_names[param_cnt] == NULL) {
				result = WERR_NOMEM;
				d_fprintf(stderr, _("Failed to create share: %s\n"),
						win_errstr(result));
				goto error;
			}

			/* place param_values */
			tmp_share.param_values[param_cnt++] = talloc_strdup(frame, s);
			if (tmp_share.param_values[param_cnt - 1] == NULL) {
				result = WERR_NOMEM;
				d_fprintf(stderr, _("Failed to create share: %s\n"),
						win_errstr(result));
				goto error;
			}
		}
	}
	/* place the includes last */
	for (i = 0; i < includes_cnt; i++) {
		tmp_share.param_names[param_cnt] = talloc_strdup(frame, "include");
		if (tmp_share.param_names[param_cnt] == NULL) {
				result = WERR_NOMEM;
				d_fprintf(stderr, _("Failed to create share: %s\n"),
						win_errstr(result));
				goto error;
		}

		tmp_share.param_values[param_cnt++] = talloc_strdup(frame, multi_s[i]);
		if (tmp_share.param_values[param_cnt - 1] == NULL) {
				result = WERR_NOMEM;
				d_fprintf(stderr, _("Failed to create share: %s\n"),
						win_errstr(result));
				goto error;
		}
	}

	/* move everything to the main memory ctx */
	for (i = 0; i < param_cnt; i++) {
		tmp_share.param_names[i] = talloc_move(mem_ctx, &tmp_share.param_names[i]);
		tmp_share.param_values[i] = talloc_move(mem_ctx, &tmp_share.param_values[i]);
	}

	tmp_share.name = talloc_move(mem_ctx, &tmp_share.name);
	tmp_share.param_names = talloc_move(mem_ctx, &tmp_share.param_names);
	tmp_share.param_values = talloc_move(mem_ctx, &tmp_share.param_values);
	/* out parameter */
	*share = tmp_share;
error:
	/* close child */
	dcerpc_winreg_CloseKey(b, frame, &child_hnd, &_werr);
	*werr = result;
	TALLOC_FREE(frame);
	return status;
}

/*
 * The function prints the shares held as smbconf_service structs
 * in a smbconf file format.
 */
static int rpc_conf_print_shares(uint32_t num_shares,
				 struct smbconf_service *shares)
{

	uint32_t share_count, param_count;
	const char *indent = "\t";

	if (num_shares == 0) {
		return 0;
	}

	for (share_count = 0; share_count < num_shares; share_count++) {
		d_printf("\n");
		if (shares[share_count].name != NULL) {
		d_printf("[%s]\n", shares[share_count].name);
		}

		for (param_count = 0;
		     param_count < shares[share_count].num_params;
		     param_count++)
		{
			d_printf("%s%s = %s\n",
				 indent,
				 shares[share_count].param_names[param_count],
				 shares[share_count].param_values[param_count]);
		}
	}
	d_printf("\n");

	return 0;

}

/*
 * The function openes the registry key
 * HKLM/Software/Samba/smbconf with the give access_mask
 */
static NTSTATUS rpc_conf_open_conf(TALLOC_CTX *mem_ctx,
				   struct dcerpc_binding_handle *b,
				   uint32_t access_mask,
				   struct policy_handle *hive_hnd,
				   struct policy_handle *key_hnd,
				   WERROR *werr)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR result = WERR_OK;
	WERROR _werr;
	struct policy_handle tmp_hive_hnd, tmp_key_hnd;
	struct winreg_String key;

	ZERO_STRUCT(key);

	status = dcerpc_winreg_OpenHKLM(b, frame, NULL,
			access_mask, &tmp_hive_hnd, &result);

	/*
	 * print no error messages if it is a read only open
	 * and key does not exist
	 * error still gets returned
	 */

	if (access_mask == REG_KEY_READ &&
	    W_ERROR_EQUAL(result, WERR_BADFILE))
	{
		goto error;
	}

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("Failed to open hive: %s\n"),
				nt_errstr(status));
		goto error;
	}
	if (!W_ERROR_IS_OK(result)) {
		d_fprintf(stderr, _("Failed to open hive: %s\n"),
				win_errstr(result));
		goto error;
	}

	key.name = confpath;
	status = dcerpc_winreg_OpenKey(b, frame, &tmp_hive_hnd, key, 0,
				       access_mask, &tmp_key_hnd, &result);

	/*
	 * print no error messages if it is a read only open
	 * and key does not exist
	 * error still gets returned
	 */

	if (access_mask == REG_KEY_READ &&
	    W_ERROR_EQUAL(result, WERR_BADFILE))
	{
		goto error;
	}

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("Failed to open smbconf key: %s\n"),
				nt_errstr(status));
		dcerpc_winreg_CloseKey(b, frame, &tmp_hive_hnd, &_werr);
		goto error;
	}
	if (!(W_ERROR_IS_OK(result))) {
		d_fprintf(stderr, _("Failed to open smbconf key: %s\n"),
			win_errstr(result));
		dcerpc_winreg_CloseKey(b, frame, &tmp_hive_hnd, &_werr);
		goto error;
	}

	*hive_hnd = tmp_hive_hnd;
	*key_hnd = tmp_key_hnd;

error:
	TALLOC_FREE(frame);
	*werr = result;

	return status;
}

/**********************************************************
 *
 * internal functions that provide the functionality
 * net rpc conf
 *
 **********************************************************/

static NTSTATUS rpc_conf_listshares_internal(struct net_context *c,
					     const struct dom_sid *domain_sid,
					     const char *domain_name,
					     struct cli_state *cli,
					     struct rpc_pipe_client *pipe_hnd,
					     TALLOC_CTX *mem_ctx,
					     int argc,
					     const char **argv )
{

	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd;
	uint32_t num_subkeys;
	uint32_t i;
	const char **subkeys = NULL;


	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);


	if (argc != 0 || c->display_usage) {
		rpc_conf_listshares_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}


	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	status = dcerpc_winreg_enum_keys(frame,
					 b,
					 &key_hnd,
					 &num_subkeys,
					 &subkeys,
					 &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("Failed to enumerate keys: %s\n"),
				nt_errstr(status));
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		d_fprintf(stderr, _("Failed to enumerate keys: %s\n"),
				win_errstr(werr));
		goto error;
	}

	for (i = 0; i < num_subkeys; i++) {
		d_printf("%s\n", subkeys[i]);
	}

error:
	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;;
}

static NTSTATUS rpc_conf_delshare_internal(struct net_context *c,
					   const struct dom_sid *domain_sid,
					   const char *domain_name,
					   struct cli_state *cli,
					   struct rpc_pipe_client *pipe_hnd,
					   TALLOC_CTX *mem_ctx,
					   int argc,
					   const char **argv )
{

	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd;

	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);


	if (argc != 1 || c->display_usage) {
		rpc_conf_delshare_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_ALL,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	status = dcerpc_winreg_delete_subkeys_recursive(frame,
							b,
							&key_hnd,
							REG_KEY_ALL,
							argv[0],
							&werr);

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr,
			  "winreg_delete_subkeys: Could not delete key %s: %s\n",
			  argv[0], nt_errstr(status));
		goto error;
	}

	if (W_ERROR_EQUAL(werr, WERR_BADFILE)){
		d_fprintf(stderr, _("ERROR: Key does not exist\n"));
	}


	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr,
			  "winreg_delete_subkeys: Could not delete key %s: %s\n",
			  argv[0], win_errstr(werr));
		goto error;
	}

error:
	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);

	TALLOC_FREE(frame);

	return status;
}

static NTSTATUS rpc_conf_list_internal(struct net_context *c,
				       const struct dom_sid *domain_sid,
				       const char *domain_name,
				       struct cli_state *cli,
				       struct rpc_pipe_client *pipe_hnd,
				       TALLOC_CTX *mem_ctx,
				       int argc,
				       const char **argv )
{

	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd;
	uint32_t num_subkeys;
	uint32_t i;
	struct smbconf_service *shares;
	const char **subkeys = NULL;


	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);


	if (argc != 0 || c->display_usage) {
		rpc_conf_list_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	status = dcerpc_winreg_enum_keys(frame,
					 b,
					 &key_hnd,
					 &num_subkeys,
					 &subkeys,
					 &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("Failed to enumerate keys: %s\n"),
				nt_errstr(status));
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		d_fprintf(stderr, _("Failed to enumerate keys: %s\n"),
				win_errstr(werr));
		goto error;
	}

	if (num_subkeys == 0) {
		dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
		dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	/* get info from each subkey */
	shares = talloc_zero_array(frame, struct smbconf_service, num_subkeys);
	if (shares == NULL) {
		werr = WERR_NOMEM;
		d_fprintf(stderr, _("Failed to create shares: %s\n"),
				win_errstr(werr));
		goto error;

	}

	for (i = 0; i < num_subkeys; i++) {
		/* get each share and place it in the shares array */
		status = rpc_conf_get_share(frame,
				b,
				&key_hnd,
				subkeys[i],
				&shares[i],
				&werr);
		if (!(NT_STATUS_IS_OK(status))) {
			goto error;
		}
		if (!(W_ERROR_IS_OK(werr))) {
			goto error;
		}

	}
	/* print the shares array */
	rpc_conf_print_shares(num_subkeys, shares);

error:
	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;

}

static NTSTATUS rpc_conf_drop_internal(struct net_context *c,
				       const struct dom_sid *domain_sid,
				       const char *domain_name,
				       struct cli_state *cli,
				       struct rpc_pipe_client *pipe_hnd,
				       TALLOC_CTX *mem_ctx,
				       int argc,
				       const char **argv )
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd;
	const char *keyname = confpath;
	struct winreg_String wkey, wkeyclass;
	enum winreg_CreateAction action = REG_ACTION_NONE;


	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);


	if (argc != 0 || c->display_usage) {
		rpc_conf_drop_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_ALL,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	status = dcerpc_winreg_delete_subkeys_recursive(frame,
							b,
							&hive_hnd,
							REG_KEY_ALL,
							keyname,
							&werr);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("winreg_delete_subkeys: Could not delete key %s: %s\n",
			  keyname, nt_errstr(status));
		goto error;
	}

	if (!W_ERROR_IS_OK(werr)) {
		d_printf("winreg_delete_subkeys: Could not delete key %s: %s\n",
			  keyname, win_errstr(werr));
		goto error;
	}

	ZERO_STRUCT(wkey);
	wkey.name = keyname;
	ZERO_STRUCT(wkeyclass);
	wkeyclass.name = "";
	action = REG_ACTION_NONE;

	status = dcerpc_winreg_CreateKey(b,
					 frame,
					 &hive_hnd,
					 wkey,
					 wkeyclass,
					 0,
					 REG_KEY_ALL,
					 NULL,
					 &key_hnd,
					 &action,
					 &werr);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("winreg_CreateKey: Could not create smbconf key\n");
		goto error;
	}

	if (!W_ERROR_IS_OK(werr)) {
		d_printf("winreg_CreateKey: Could not create smbconf key\n");
		goto error;
	}


error:
	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS rpc_conf_import_internal(struct net_context *c,
					 const struct dom_sid *domain_sid,
					 const char *domain_name,
					 struct cli_state *cli,
					 struct rpc_pipe_client *pipe_hnd,
					 TALLOC_CTX *mem_ctx,
					 int argc,
					 const char **argv )
{

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	struct policy_handle hive_hnd, key_hnd;

	const char *filename = NULL;
	const char *servicename = NULL;
	char *conf_source = NULL;
	TALLOC_CTX *frame;
	struct smbconf_ctx *txt_ctx;
	struct smbconf_service *service = NULL;
	struct smbconf_service **services = NULL;
	uint32_t num_shares, i;
	sbcErr err = SBC_ERR_UNKNOWN_FAILURE;

	WERROR werr = WERR_OK;
	NTSTATUS status = NT_STATUS_OK;

	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);

	frame = talloc_stackframe();

	if (c->display_usage) {
		rpc_conf_import_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	switch (argc) {
		case 0:
		default:
			rpc_conf_import_usage(c, argc, argv);
			status = NT_STATUS_INVALID_PARAMETER;
			goto error;
		case 2:
			servicename = talloc_strdup(frame, argv[1]);
			if (servicename == NULL) {
				d_printf(_("error: out of memory!\n"));
				goto error;
			}
		case 1:
			filename = argv[0];
			break;
	}

	DEBUG(3,("rpc_conf_import: reading configuration from file %s.\n",
		filename));

	conf_source = talloc_asprintf(frame, "file:%s", filename);
	if (conf_source == NULL) {
		d_fprintf(stderr, _("error: out of memory!\n"));
		goto error;
	}

	err = smbconf_init(frame, &txt_ctx, conf_source);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("error loading file '%s': %s\n"), filename,
			 sbcErrorString(err));
		goto error;
	}

	if (c->opt_testmode) {
		d_printf(_("\nTEST MODE - "
			 "would import the following configuration:\n\n"));
	}

	if (servicename != NULL) {
		err = smbconf_get_share(txt_ctx, frame,
					servicename,
					&service);
		if (!SBC_ERROR_IS_OK(err)) {
			goto error;
		}

		num_shares = 1;

	} else {

		err = smbconf_get_config(txt_ctx, frame,
					  &num_shares,
					  &services);
		if (!SBC_ERROR_IS_OK(err)) {
			goto error;
		}
	}

	if (c->opt_testmode) {
		if (servicename != NULL) {
			rpc_conf_print_shares(1, service);
		}
		for (i = 0; i < num_shares; i++) {
			rpc_conf_print_shares(1, services[i]);
		}
		goto error;
	}

	status = rpc_conf_drop_internal(c,
			       domain_sid,
			       domain_name,
			       cli,
			       pipe_hnd,
			       frame,
			       0,
			       NULL );

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	if (servicename != NULL) {
		status = rpc_conf_set_share(frame,
					    b,
					    &key_hnd,
					    service,
					    &werr);

		if (!(NT_STATUS_IS_OK(status))) {
			goto error;
		}

		if (!(W_ERROR_IS_OK(werr))) {
			goto error;
		}

	} else {

		for (i = 0; i < num_shares; i++) {
			status = rpc_conf_set_share(frame,
					b,
					&key_hnd,
					services[i],
					&werr);

			if (!(NT_STATUS_IS_OK(status))) {
				goto error;
			}

			if (!(W_ERROR_IS_OK(werr))) {
				goto error;
			}

		}
	}

error:
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, "ERROR: %s\n", sbcErrorString(err));
	}

	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS rpc_conf_showshare_internal(struct net_context *c,
					    const struct dom_sid *domain_sid,
					    const char *domain_name,
					    struct cli_state *cli,
					    struct rpc_pipe_client *pipe_hnd,
					    TALLOC_CTX *mem_ctx,
					    int argc,
					    const char **argv )
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd;
	struct smbconf_service *service = NULL;
	const char *sharename = NULL;


	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);


	if (argc != 1 || c->display_usage) {
		rpc_conf_showshare_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	sharename = talloc_strdup(frame, argv[0]);
	if (sharename == NULL) {
		werr = WERR_NOMEM;
		d_fprintf(stderr, _("Failed to create share: %s\n"),
				win_errstr(werr));
		goto error;
	}

	service = talloc(frame, struct smbconf_service);
	if (service == NULL) {
		werr = WERR_NOMEM;
		d_fprintf(stderr, _("Failed to create share: %s\n"),
				win_errstr(werr));
		goto error;
	}

	status = rpc_conf_get_share(frame,
			b,
			&key_hnd,
			sharename,
			service,
			&werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}
	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	rpc_conf_print_shares(1, service);

error:
	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS rpc_conf_addshare_internal(struct net_context *c,
					   const struct dom_sid *domain_sid,
					   const char *domain_name,
					   struct cli_state *cli,
					   struct rpc_pipe_client *pipe_hnd,
					   TALLOC_CTX *mem_ctx,
					   int argc,
					   const char **argv )
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd, share_hnd;
	char *sharename = NULL;
	const char *path = NULL;
	const char *comment = NULL;
	const char *guest_ok = "no";
	const char *read_only = "yes";
	struct winreg_String key, keyclass;
	enum winreg_CreateAction action = 0;


	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);
	ZERO_STRUCT(share_hnd);

	ZERO_STRUCT(key);
	ZERO_STRUCT(keyclass);

	if (c->display_usage) {
		rpc_conf_addshare_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	switch (argc) {
		case 0:
		case 1:
		default:
			rpc_conf_addshare_usage(c, argc, argv);
			status = NT_STATUS_INVALID_PARAMETER;
			goto error;
		case 5:
			comment = argv[4];
		case 4:
			if (!strnequal(argv[3], "guest_ok=", 9)) {
				rpc_conf_addshare_usage(c, argc, argv);
				status = NT_STATUS_INVALID_PARAMETER;
				goto error;
			}
			switch (argv[3][9]) {
				case 'y':
				case 'Y':
					guest_ok = "yes";
					break;
				case 'n':
				case 'N':
					guest_ok = "no";
					break;
				default:
					rpc_conf_addshare_usage(c, argc, argv);
					status = NT_STATUS_INVALID_PARAMETER;
					goto error;
			}
		case 3:
			if (!strnequal(argv[2], "writeable=", 10)) {
				rpc_conf_addshare_usage(c, argc, argv);
				status = NT_STATUS_INVALID_PARAMETER;
				goto error;
			}
			switch (argv[2][10]) {
				case 'y':
				case 'Y':
					read_only = "no";
					break;
				case 'n':
				case 'N':
					read_only = "yes";
					break;
				default:
					rpc_conf_addshare_usage(c, argc, argv);
					status = NT_STATUS_INVALID_PARAMETER;
					goto error;
			}
		case 2:
			path = argv[1];
			sharename = talloc_strdup(frame, argv[0]);
			if (sharename == NULL) {
				d_printf(_("error: out of memory!\n"));
				goto error;
			}

			break;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	key.name = argv[0];
	keyclass.name = "";

	status = dcerpc_winreg_CreateKey(b, frame, &key_hnd, key, keyclass,
			0, REG_KEY_READ, NULL, &share_hnd,
			&action, &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("ERROR: Could not create share key '%s'\n%s\n"),
				argv[0], nt_errstr(status));
		goto error;
	}

	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("ERROR: Could not create share key '%s'\n%s\n"),
				argv[0], win_errstr(werr));
		goto error;
	}

	switch (action) {
		case REG_ACTION_NONE:
			werr = WERR_CREATE_FAILED;
			d_fprintf(stderr, _("ERROR: Could not create share key '%s'\n%s\n"),
				argv[0], win_errstr(werr));
			goto error;
		case REG_CREATED_NEW_KEY:
			DEBUG(5, ("net rpc conf setincludes:"
					"createkey created %s\n", argv[0]));
			break;
		case REG_OPENED_EXISTING_KEY:
			d_fprintf(stderr, _("ERROR: Share '%s' already exists\n"), argv[0]);
			status = NT_STATUS_INVALID_PARAMETER;
			goto error;
	}

	/* set the path parameter */
	status = dcerpc_winreg_set_sz(frame, b, &share_hnd,
					"path", path, &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
				" with value %s\n %s\n",
				"path", path, nt_errstr(status));
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
				" with value %s\n %s\n",
				"path", path, win_errstr(werr));
		goto error;
	}

	/* set the writeable parameter */
	status = dcerpc_winreg_set_sz(frame, b, &share_hnd,
					"read only", read_only, &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
				" with value %s\n %s\n",
				"read only", read_only, nt_errstr(status));
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
				" with value %s\n %s\n",
				"read only", read_only, win_errstr(werr));
		goto error;
	}

	/* set the guest ok parameter */
	status = dcerpc_winreg_set_sz(frame, b, &share_hnd,
					"guest ok", guest_ok, &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
				" with value %s\n %s\n",
				"guest ok", guest_ok, nt_errstr(status));
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
				" with value %s\n %s\n",
				"guest ok", guest_ok, win_errstr(werr));
		goto error;
	}

	if (argc == 5) {
		/* set the comment parameter */
		status = dcerpc_winreg_set_sz(frame, b, &share_hnd,
						"comment", comment, &werr);

		if (!(NT_STATUS_IS_OK(status))) {
			d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
					" with value %s\n %s\n",
					"comment", comment, nt_errstr(status));
			goto error;
		}

		if (!(W_ERROR_IS_OK(werr))) {
			d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
					" with value %s\n %s\n",
					"comment", comment, win_errstr(werr));
			goto error;
		}
	}
error:
	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &share_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS rpc_conf_getparm_internal(struct net_context *c,
					  const struct dom_sid *domain_sid,
					  const char *domain_name,
					  struct cli_state *cli,
					  struct rpc_pipe_client *pipe_hnd,
					  TALLOC_CTX *mem_ctx,
					  int argc,
					  const char **argv )
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd;
	struct smbconf_service *service = NULL;

	bool param_is_set = false;
	uint32_t param_count;

	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);


	if (argc != 2 || c->display_usage) {
		rpc_conf_getparm_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}


	service = talloc(frame, struct smbconf_service);

	status = rpc_conf_get_share(frame,
			            b,
				    &key_hnd,
				    argv[0],
				    service,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
			goto error;
	}

	if (W_ERROR_EQUAL(werr, WERR_BADFILE)) {
		d_fprintf(stderr, _("ERROR: Share %s does not exist\n"),
				argv[0]);
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
			goto error;
	}

	for (param_count = 0;
	     param_count < service->num_params;
	     param_count++)
	{
		/* should includes also be printed? */
		if (strcmp(service->param_names[param_count], argv[1]) == 0) {
			d_printf(_("%s\n"),
				service->param_values[param_count]);
			param_is_set = true;
		}
	}

	if (!param_is_set) {
		d_fprintf(stderr, _("ERROR: Given parameter '%s' has not been set\n"),
				argv[1]);
		werr = WERR_BADFILE;
		goto error;
	}

error:

	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;

}

static NTSTATUS rpc_conf_setparm_internal(struct net_context *c,
					  const struct dom_sid *domain_sid,
					  const char *domain_name,
					  struct cli_state *cli,
					  struct rpc_pipe_client *pipe_hnd,
					  TALLOC_CTX *mem_ctx,
					  int argc,
					  const char **argv )
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd, share_hnd;

	struct winreg_String key, keyclass;
	enum winreg_CreateAction action = 0;

	const char *service_name, *param_name, *valstr;

	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);
	ZERO_STRUCT(share_hnd);

	ZERO_STRUCT(key);
	ZERO_STRUCT(keyclass);

	if (argc != 3 || c->display_usage) {
		rpc_conf_setparm_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	service_name = argv[0];
	param_name = argv[1];
	valstr = argv[2];

	key.name = service_name;
	keyclass.name = "";

	status = dcerpc_winreg_CreateKey(b, frame, &key_hnd, key, keyclass,
			0, REG_KEY_READ, NULL, &share_hnd,
			&action, &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("ERROR: Could not create share key '%s'\n%s\n"),
			  service_name, nt_errstr(status));
		goto error;
	}

	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("ERROR: Could not create share key '%s'\n%s\n"),
			  service_name, win_errstr(werr));
		goto error;
	}

	switch (action) {
		case REG_ACTION_NONE:
			werr = WERR_CREATE_FAILED;
			d_fprintf(stderr, _("ERROR: Could not create share key '%s'\n%s\n"),
				  service_name, win_errstr(werr));
			goto error;
		case REG_CREATED_NEW_KEY:
			DEBUG(5, ("net rpc conf setparm:"
				  "createkey created %s\n", service_name));
			break;
		case REG_OPENED_EXISTING_KEY:
			DEBUG(5, ("net rpc conf setparm:"
				  "createkey opened existing %s\n",
				  service_name));

			/* delete posibly existing value */
			status = rpc_conf_del_value(frame,
						    b,
						    &key_hnd,
						    service_name,
						    param_name,
						    &werr);

			if (!(NT_STATUS_IS_OK(status))) {
				goto error;
			}

			if (!(W_ERROR_IS_OK(werr))) {
				goto error;
			}

			break;
	}

	/*
	 * check if parameter is valid for writing
	 */

	if (!net_conf_param_valid(service_name, param_name, valstr)) {
		werr = WERR_INVALID_PARAM;
		goto error;
	}

	/* set the parameter */
	status = dcerpc_winreg_set_sz(frame, b, &share_hnd,
				      param_name, valstr, &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
				" with value %s\n %s\n",
				param_name, valstr, nt_errstr(status));
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		d_fprintf(stderr, "ERROR: Could not set parameter '%s'"
				" with value %s\n %s\n",
				param_name, valstr, win_errstr(werr));
		goto error;
	}

error:

	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &share_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS rpc_conf_delparm_internal(struct net_context *c,
					  const struct dom_sid *domain_sid,
					  const char *domain_name,
					  struct cli_state *cli,
					  struct rpc_pipe_client *pipe_hnd,
					  TALLOC_CTX *mem_ctx,
					  int argc,
					  const char **argv )
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd;


	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);


	if (argc != 2 || c->display_usage) {
		rpc_conf_delparm_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	status = rpc_conf_del_value(frame,
			            b,
				    &key_hnd,
				    argv[0],
				    argv[1],
				    &werr);

error:

	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;

}

static NTSTATUS rpc_conf_getincludes_internal(struct net_context *c,
					      const struct dom_sid *domain_sid,
					      const char *domain_name,
					      struct cli_state *cli,
					      struct rpc_pipe_client *pipe_hnd,
					      TALLOC_CTX *mem_ctx,
					      int argc,
					      const char **argv )
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd;
	struct smbconf_service *service = NULL;

	uint32_t param_count;


	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);


	if (argc != 1 || c->display_usage) {
		rpc_conf_getincludes_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	service = talloc(frame, struct smbconf_service);

	status = rpc_conf_get_share(frame,
			            b,
				    &key_hnd,
				    argv[0],
				    service,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
			goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
			goto error;
	}

	for (param_count = 0;
	     param_count < service->num_params;
	     param_count++)
	{
		if (strcmp(service->param_names[param_count], "include") == 0) {
			d_printf(_("%s = %s\n"),
				service->param_names[param_count],
				service->param_values[param_count]);
		}
	}

error:

	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;

}

static NTSTATUS rpc_conf_setincludes_internal(struct net_context *c,
					      const struct dom_sid *domain_sid,
					      const char *domain_name,
					      struct cli_state *cli,
					      struct rpc_pipe_client *pipe_hnd,
					      TALLOC_CTX *mem_ctx,
					      int argc,
					      const char **argv )
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd, share_hnd;

	struct winreg_String key, keyclass;
	enum winreg_CreateAction action = 0;

	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);
	ZERO_STRUCT(share_hnd);

	ZERO_STRUCT(key);
	ZERO_STRUCT(keyclass);

	if (argc < 1 || c->display_usage) {
		rpc_conf_setincludes_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	key.name = argv[0];
	keyclass.name = "";

	status = dcerpc_winreg_CreateKey(b, frame, &key_hnd, key, keyclass,
			0, REG_KEY_READ, NULL, &share_hnd,
			&action, &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, _("ERROR: Could not create share key '%s'\n%s\n"),
				argv[0], nt_errstr(status));
		goto error;
	}

	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("ERROR: Could not create share key '%s'\n%s\n"),
				argv[0], win_errstr(werr));
		goto error;
	}

	switch (action) {
		case REG_ACTION_NONE:
			/* Is there any other way to treat this? */
			werr = WERR_CREATE_FAILED;
			d_fprintf(stderr, _("ERROR: Could not create share key '%s'\n%s\n"),
				argv[0], win_errstr(werr));
			goto error;
		case REG_CREATED_NEW_KEY:
			DEBUG(5, ("net rpc conf setincludes:"
					"createkey created %s\n", argv[0]));
			break;
		case REG_OPENED_EXISTING_KEY:
			DEBUG(5, ("net rpc conf setincludes:"
					"createkey opened existing %s\n", argv[0]));

			/* delete posibly existing value */
			status = rpc_conf_del_value(frame,
						    b,
						    &key_hnd,
						    argv[0],
						    "includes",
						    &werr);

			if (!(NT_STATUS_IS_OK(status))) {
				goto error;
			}

			if (!(W_ERROR_IS_OK(werr))) {
				goto error;
			}
			break;
	}

	/* set the 'includes' values */
	status = dcerpc_winreg_set_multi_sz(frame, b, &share_hnd,
					    "includes", argv + 1, &werr);
	if (!(NT_STATUS_IS_OK(status))) {
		d_fprintf(stderr, "ERROR: Could not set includes\n %s\n",
				nt_errstr(status));
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		d_fprintf(stderr, "ERROR: Could not set includes\n %s\n",
				win_errstr(werr));
		goto error;
	}

error:

	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &share_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS rpc_conf_delincludes_internal(struct net_context *c,
					      const struct dom_sid *domain_sid,
					      const char *domain_name,
					      struct cli_state *cli,
					      struct rpc_pipe_client *pipe_hnd,
					      TALLOC_CTX *mem_ctx,
					      int argc,
					      const char **argv )
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	WERROR werr = WERR_OK;
	WERROR _werr;

	struct dcerpc_binding_handle *b = pipe_hnd->binding_handle;

	/* key info */
	struct policy_handle hive_hnd, key_hnd;


	ZERO_STRUCT(hive_hnd);
	ZERO_STRUCT(key_hnd);


	if (argc != 1 || c->display_usage) {
		rpc_conf_delincludes_usage(c, argc, argv);
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	status = rpc_conf_open_conf(frame,
				    b,
				    REG_KEY_READ,
				    &hive_hnd,
				    &key_hnd,
				    &werr);

	if (!(NT_STATUS_IS_OK(status))) {
		goto error;
	}

	if (!(W_ERROR_IS_OK(werr))) {
		goto error;
	}

	status = rpc_conf_del_value(frame,
			            b,
				    &key_hnd,
				    argv[0],
				    "includes",
				    &werr);

error:

	if (!(W_ERROR_IS_OK(werr))) {
		status =  werror_to_ntstatus(werr);
	}

	dcerpc_winreg_CloseKey(b, frame, &hive_hnd, &_werr);
	dcerpc_winreg_CloseKey(b, frame, &key_hnd, &_werr);

	TALLOC_FREE(frame);
	return status;

}

/**********************************************************
 *
 * Functions that run the rpc commands for net rpc conf modules
 *
 **********************************************************/

static int rpc_conf_drop(struct net_context *c, int argc,
				const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_drop_internal, argc, argv );

}

static int rpc_conf_showshare(struct net_context *c, int argc,
				const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_showshare_internal, argc, argv );
}

static int rpc_conf_addshare(struct net_context *c, int argc,
				const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_addshare_internal, argc, argv );
}

static int rpc_conf_listshares(struct net_context *c, int argc,
				const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_listshares_internal, argc, argv );
}

static int rpc_conf_list(struct net_context *c, int argc,
			     const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_list_internal, argc, argv );
}

static int rpc_conf_import(struct net_context *c, int argc,
				const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_import_internal, argc, argv );
}
static int rpc_conf_delshare(struct net_context *c, int argc,
			     const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_delshare_internal, argc, argv );
}

static int rpc_conf_getparm(struct net_context *c, int argc,
			     const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_getparm_internal, argc, argv );
}

static int rpc_conf_setparm(struct net_context *c, int argc,
				const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_setparm_internal, argc, argv );
}
static int rpc_conf_delparm(struct net_context *c, int argc,
				const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_delparm_internal, argc, argv );
}

static int rpc_conf_getincludes(struct net_context *c, int argc,
			     const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_getincludes_internal, argc, argv );
}

static int rpc_conf_setincludes(struct net_context *c, int argc,
				const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_setincludes_internal, argc, argv );
}

static int rpc_conf_delincludes(struct net_context *c, int argc,
				const char **argv)
{
	return run_rpc_command(c, NULL, &ndr_table_winreg, 0,
		rpc_conf_delincludes_internal, argc, argv );
}

/* function calls */
int net_rpc_conf(struct net_context *c, int argc,
		 const char **argv)
{
	struct functable func_table[] = {
		{
			"list",
			rpc_conf_list,
			NET_TRANSPORT_RPC,
			N_("Dump the complete remote configuration in smb.conf like "
			   "format."),
			N_("net rpc conf list\n"
			   "    Dump the complete remote configuration in smb.conf "
			   "like format.")

		},
		{
			"import",
			rpc_conf_import,
			NET_TRANSPORT_RPC,
			N_("Import configuration from file in smb.conf "
			   "format."),
			N_("net rpc conf import\n"
			   "    Import configuration from file in smb.conf "
			   "format.")
		},
		{
			"listshares",
			rpc_conf_listshares,
			NET_TRANSPORT_RPC,
			N_("List the remote share names."),
			N_("net rpc conf list\n"
			   "    List the remote share names.")

		},
		{
			"drop",
			rpc_conf_drop,
			NET_TRANSPORT_RPC,
			N_("Delete the complete remote configuration."),
			N_("net rpc conf drop\n"
			   "    Delete the complete remote configuration.")

		},
		{
			"showshare",
			rpc_conf_showshare,
			NET_TRANSPORT_RPC,
			N_("Show the definition of a remote share."),
			N_("net rpc conf showshare\n"
			   "    Show the definition of a remote share.")

		},
		{
			"addshare",
			rpc_conf_addshare,
			NET_TRANSPORT_RPC,
			N_("Create a new remote share."),
			N_("net rpc conf addshare\n"
			   "    Create a new remote share.")
		},
		{
			"delshare",
			rpc_conf_delshare,
			NET_TRANSPORT_RPC,
			N_("Delete a remote share."),
			N_("net rpc conf delshare\n"
			   "    Delete a remote share.")
		},
		{
			"getparm",
			rpc_conf_getparm,
			NET_TRANSPORT_RPC,
			N_("Retrieve the value of a parameter."),
			N_("net rpc conf getparm\n"
			   "    Retrieve the value of a parameter.")
		},
		{
			"setparm",
			rpc_conf_setparm,
			NET_TRANSPORT_RPC,
			N_("Store a parameter."),
			N_("net rpc conf setparm\n"
			   "    Store a parameter.")
		},
		{
			"delparm",
			rpc_conf_delparm,
			NET_TRANSPORT_RPC,
			N_("Delete a parameter."),
			N_("net rpc conf delparm\n"
			   "    Delete a parameter.")
		},
		{
			"getincludes",
			rpc_conf_getincludes,
			NET_TRANSPORT_RPC,
			N_("Show the includes of a share definition."),
			N_("net rpc conf getincludes\n"
			   "    Show the includes of a share definition.")
		},
		{
			"setincludes",
			rpc_conf_setincludes,
			NET_TRANSPORT_RPC,
			N_("Set includes for a share."),
			N_("net rpc conf setincludes\n"
			   "    Set includes for a share.")
		},
		{
			"delincludes",
			rpc_conf_delincludes,
			NET_TRANSPORT_RPC,
			N_("Delete includes from a share definition."),
			N_("net rpc conf delincludes\n"
			   "    Delete includes from a share definition.")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net rpc conf", func_table);

}
