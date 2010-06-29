/*
 * Samba Unix/Linux SMB client library
 * Distributed SMB/CIFS Server Management Utility
 * Local registry interface
 *
 * Copyright (C) Michael Adam 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "registry.h"
#include "registry/reg_util_token.h"
#include "utils/net.h"
#include "utils/net_registry_util.h"
#include "include/g_lock.h"

/*
 *
 * Helper functions
 *
 */

/**
 * split given path into hive and remaining path and open the hive key
 */
static WERROR open_hive(TALLOC_CTX *ctx, const char *path,
			uint32 desired_access,
			struct registry_key **hive,
			char **subkeyname)
{
	WERROR werr;
	NT_USER_TOKEN *token = NULL;
	char *hivename = NULL;
	char *tmp_subkeyname = NULL;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	if ((hive == NULL) || (subkeyname == NULL)) {
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	werr = split_hive_key(tmp_ctx, path, &hivename, &tmp_subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}
	*subkeyname = talloc_strdup(ctx, tmp_subkeyname);
	if (*subkeyname == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}

	werr = ntstatus_to_werror(registry_create_admin_token(tmp_ctx, &token));
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = reg_openhive(ctx, hivename, desired_access, token, hive);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return werr;
}

static WERROR open_key(TALLOC_CTX *ctx, const char *path,
		       uint32 desired_access,
		       struct registry_key **key)
{
	WERROR werr;
	char *subkey_name = NULL;
	struct registry_key *hive = NULL;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	if ((path == NULL) || (key == NULL)) {
		return WERR_INVALID_PARAM;
	}

	werr = open_hive(tmp_ctx, path, desired_access, &hive, &subkey_name);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_hive failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_openkey(ctx, hive, subkey_name, desired_access, key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_openkey failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return werr;
}

/*
 *
 * the main "net registry" function implementations
 *
 */

static int net_registry_enumerate(struct net_context *c, int argc,
				  const char **argv)
{
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	char *subkey_name;
	NTTIME modtime;
	uint32_t count;
	char *valname = NULL;
	struct registry_value *valvalue = NULL;
	int ret = -1;

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry enumerate <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry enumerate 'HKLM\\Software\\Samba'\n"));
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	for (count = 0;
	     werr = reg_enumkey(ctx, key, count, &subkey_name, &modtime),
	     W_ERROR_IS_OK(werr);
	     count++)
	{
		print_registry_key(subkey_name, &modtime);
	}
	if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
		goto done;
	}

	for (count = 0;
	     werr = reg_enumvalue(ctx, key, count, &valname, &valvalue),
	     W_ERROR_IS_OK(werr);
	     count++)
	{
		print_registry_value_with_name(valname, valvalue);
	}
	if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
		goto done;
	}

	ret = 0;
done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_createkey(struct net_context *c, int argc,
				  const char **argv)
{
	WERROR werr;
	enum winreg_CreateAction action;
	char *subkeyname;
	struct registry_key *hivekey = NULL;
	struct registry_key *subkey = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry createkey <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry createkey "
			   "'HKLM\\Software\\Samba\\smbconf.127.0.0.1'\n"));
		goto done;
	}
	if (strlen(argv[0]) == 0) {
		d_fprintf(stderr, _("error: zero length key name given\n"));
		goto done;
	}

	werr = open_hive(ctx, argv[0], REG_KEY_WRITE, &hivekey, &subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_hive failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_createkey(ctx, hivekey, subkeyname, REG_KEY_WRITE,
			     &subkey, &action);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_createkey failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}
	switch (action) {
		case REG_ACTION_NONE:
			d_printf(_("createkey did nothing -- huh?\n"));
			break;
		case REG_CREATED_NEW_KEY:
			d_printf(_("createkey created %s\n"), argv[0]);
			break;
		case REG_OPENED_EXISTING_KEY:
			d_printf(_("createkey opened existing %s\n"), argv[0]);
			break;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_deletekey(struct net_context *c, int argc,
				  const char **argv)
{
	WERROR werr;
	char *subkeyname;
	struct registry_key *hivekey = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry deletekey <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry deletekey "
			   "'HKLM\\Software\\Samba\\smbconf.127.0.0.1'\n"));
		goto done;
	}
	if (strlen(argv[0]) == 0) {
		d_fprintf(stderr, _("error: zero length key name given\n"));
		goto done;
	}

	werr = open_hive(ctx, argv[0], REG_KEY_WRITE, &hivekey, &subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_hive %s: %s\n", _("failed"),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_deletekey(hivekey, subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "reg_deletekey %s: %s\n", _("failed"),
			  win_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_getvalue_internal(struct net_context *c, int argc,
					  const char **argv, bool raw)
{
	WERROR werr;
	int ret = -1;
	struct registry_key *key = NULL;
	struct registry_value *value = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc != 2 || c->display_usage) {
		d_fprintf(stderr, "%s\n%s",
			  _("Usage:"),
			  _("net registry getvalue <key> <valuename>\n"));
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	werr = reg_queryvalue(ctx, key, argv[1], &value);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_queryvalue failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	print_registry_value(value, raw);

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_getvalue(struct net_context *c, int argc,
				 const char **argv)
{
	return net_registry_getvalue_internal(c, argc, argv, false);
}

static int net_registry_getvalueraw(struct net_context *c, int argc,
				    const char **argv)
{
	return net_registry_getvalue_internal(c, argc, argv, true);
}

static int net_registry_setvalue(struct net_context *c, int argc,
				 const char **argv)
{
	WERROR werr;
	struct registry_value value;
	struct registry_key *key = NULL;
	int ret = -1;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc < 4 || c->display_usage) {
		d_fprintf(stderr, "%s\n%s",
			  _("Usage:"),
			  _("net registry setvalue <key> <valuename> "
			    "<type> [<val>]+\n"));
		goto done;
	}

	if (!strequal(argv[2], "multi_sz") && (argc != 4)) {
		d_fprintf(stderr, _("Too many args for type %s\n"), argv[2]);
		goto done;
	}

	if (strequal(argv[2], "dword")) {
		uint32_t v = strtoul(argv[3], NULL, 10);
		value.type = REG_DWORD;
		value.data = data_blob_talloc(ctx, NULL, 4);
		SIVAL(value.data.data, 0, v);
	} else if (strequal(argv[2], "sz")) {
		value.type = REG_SZ;
		if (!push_reg_sz(ctx, &value.data, argv[3])) {
			goto done;
		}
	} else if (strequal(argv[2], "multi_sz")) {
		const char **array;
		int count = argc - 3;
		int i;
		value.type = REG_MULTI_SZ;
		array = talloc_zero_array(ctx, const char *, count + 1);
		if (array == NULL) {
			goto done;
		}
		for (i=0; i < count; i++) {
			array[i] = talloc_strdup(array, argv[count+i]);
			if (array[i] == NULL) {
				goto done;
			}
		}
		if (!push_reg_multi_sz(ctx, &value.data, array)) {
			goto done;
		}
	} else {
		d_fprintf(stderr, _("type \"%s\" not implemented\n"), argv[2]);
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	werr = reg_setvalue(key, argv[1], &value);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_setvalue failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

struct net_registry_increment_state {
	const char *keyname;
	const char *valuename;
	uint32_t increment;
	uint32_t newvalue;
	WERROR werr;
};

static void net_registry_increment_fn(void *private_data)
{
	struct net_registry_increment_state *state =
		(struct net_registry_increment_state *)private_data;
	struct registry_value *value;
	struct registry_key *key = NULL;
	uint32_t v;

	state->werr = open_key(talloc_tos(), state->keyname,
			       REG_KEY_READ|REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(state->werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"),
			  win_errstr(state->werr));
		goto done;
	}

	state->werr = reg_queryvalue(key, key, state->valuename, &value);
	if (!W_ERROR_IS_OK(state->werr)) {
		d_fprintf(stderr, _("reg_queryvalue failed: %s\n"),
			  win_errstr(state->werr));
		goto done;
	}

	if (value->type != REG_DWORD) {
		d_fprintf(stderr, _("value not a DWORD: %s\n"),
			  str_regtype(value->type));
		goto done;
	}

	if (value->data.length < 4) {
		d_fprintf(stderr, _("value too short for regular DWORD\n"));
		goto done;
	}

	v = IVAL(value->data.data, 0);
	v += state->increment;
	state->newvalue = v;

	SIVAL(value->data.data, 0, v);

	state->werr = reg_setvalue(key, state->valuename, value);
	if (!W_ERROR_IS_OK(state->werr)) {
		d_fprintf(stderr, _("reg_setvalue failed: %s\n"),
			  win_errstr(state->werr));
		goto done;
	}

done:
	TALLOC_FREE(key);
	return;
}

static int net_registry_increment(struct net_context *c, int argc,
				  const char **argv)
{
	struct net_registry_increment_state state;
	NTSTATUS status;
	int ret = -1;

	if (argc < 2 || c->display_usage) {
		d_fprintf(stderr, "%s\n%s",
			  _("Usage:"),
			  _("net registry increment <key> <valuename> "
			    "[<increment>]\n"));
		goto done;
	}

	state.keyname = argv[0];
	state.valuename = argv[1];

	state.increment = 1;
	if (argc == 3) {
		state.increment = strtoul(argv[2], NULL, 10);
	}

	status = g_lock_do("registry_increment_lock", G_LOCK_WRITE,
			   timeval_set(600, 0),
			   net_registry_increment_fn, &state);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, _("g_lock_do failed: %s\n"),
			  nt_errstr(status));
		goto done;
	}
	if (!W_ERROR_IS_OK(state.werr)) {
		d_fprintf(stderr, _("increment failed: %s\n"),
			  win_errstr(state.werr));
		goto done;
	}

	d_printf(_("%u\n"), (unsigned)state.newvalue);

	ret = 0;

done:
	return ret;
}

static int net_registry_deletevalue(struct net_context *c, int argc,
				    const char **argv)
{
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 2 || c->display_usage) {
		d_fprintf(stderr, "%s\n%s",
			  _("Usage:"),
			  _("net registry deletevalue <key> <valuename>\n"));
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	werr = reg_deletevalue(key, argv[1]);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_deletekey failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static WERROR net_registry_getsd_internal(struct net_context *c,
					  TALLOC_CTX *mem_ctx,
					  const char *keyname,
					  struct security_descriptor **sd)
{
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	uint32_t access_mask = REG_KEY_READ |
			       SEC_FLAG_MAXIMUM_ALLOWED |
			       SEC_FLAG_SYSTEM_SECURITY;

	/*
	 * net_rpc_regsitry uses SEC_FLAG_SYSTEM_SECURITY, but access
	 * is denied with these perms right now...
	 */
	access_mask = REG_KEY_READ;

	if (sd == NULL) {
		d_fprintf(stderr, _("internal error: invalid argument\n"));
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	if (strlen(keyname) == 0) {
		d_fprintf(stderr, _("error: zero length key name given\n"));
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	werr = open_key(ctx, keyname, access_mask, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "%s%s\n", _("open_key failed: "),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_getkeysecurity(mem_ctx, key, sd);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "%s%s\n", _("reg_getkeysecurity failed: "),
			  win_errstr(werr));
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(ctx);
	return werr;
}

static int net_registry_getsd(struct net_context *c, int argc,
			      const char **argv)
{
	WERROR werr;
	int ret = -1;
	struct security_descriptor *secdesc = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry getsd <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry getsd 'HKLM\\Software\\Samba'\n"));
		goto done;
	}

	werr = net_registry_getsd_internal(c, ctx, argv[0], &secdesc);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	display_sec_desc(secdesc);

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_getsd_sddl(struct net_context *c,
				   int argc, const char **argv)
{
	WERROR werr;
	int ret = -1;
	struct security_descriptor *secdesc = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry getsd_sddl <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry getsd_sddl 'HKLM\\Software\\Samba'\n"));
		goto done;
	}

	werr = net_registry_getsd_internal(c, ctx, argv[0], &secdesc);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	d_printf("%s\n", sddl_encode(ctx, secdesc, get_global_sam_sid()));

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static WERROR net_registry_setsd_internal(struct net_context *c,
					  TALLOC_CTX *mem_ctx,
					  const char *keyname,
					  struct security_descriptor *sd)
{
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	uint32_t access_mask = REG_KEY_WRITE |
			       SEC_FLAG_MAXIMUM_ALLOWED |
			       SEC_FLAG_SYSTEM_SECURITY;

	/*
	 * net_rpc_regsitry uses SEC_FLAG_SYSTEM_SECURITY, but access
	 * is denied with these perms right now...
	 */
	access_mask = REG_KEY_WRITE;

	if (strlen(keyname) == 0) {
		d_fprintf(stderr, _("error: zero length key name given\n"));
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	werr = open_key(ctx, keyname, access_mask, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "%s%s\n", _("open_key failed: "),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_setkeysecurity(key, sd);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "%s%s\n", _("reg_setkeysecurity failed: "),
			  win_errstr(werr));
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(ctx);
	return werr;
}

static int net_registry_setsd_sddl(struct net_context *c,
				   int argc, const char **argv)
{
	WERROR werr;
	int ret = -1;
	struct security_descriptor *secdesc = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc != 2 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry setsd_sddl <path> <security_descriptor>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry setsd_sddl 'HKLM\\Software\\Samba'\n"));
		goto done;
	}

	secdesc = sddl_decode(ctx, argv[1], get_global_sam_sid());
	if (secdesc == NULL) {
		goto done;
	}

	werr = net_registry_setsd_internal(c, ctx, argv[0], secdesc);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

int net_registry(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;

	struct functable func[] = {
		{
			"enumerate",
			net_registry_enumerate,
			NET_TRANSPORT_LOCAL,
			N_("Enumerate registry keys and values"),
			N_("net registry enumerate\n"
			   "    Enumerate registry keys and values")
		},
		{
			"createkey",
			net_registry_createkey,
			NET_TRANSPORT_LOCAL,
			N_("Create a new registry key"),
			N_("net registry createkey\n"
			   "    Create a new registry key")
		},
		{
			"deletekey",
			net_registry_deletekey,
			NET_TRANSPORT_LOCAL,
			N_("Delete a registry key"),
			N_("net registry deletekey\n"
			   "    Delete a registry key")
		},
		{
			"getvalue",
			net_registry_getvalue,
			NET_TRANSPORT_LOCAL,
			N_("Print a registry value"),
			N_("net registry getvalue\n"
			   "    Print a registry value")
		},
		{
			"getvalueraw",
			net_registry_getvalueraw,
			NET_TRANSPORT_LOCAL,
			N_("Print a registry value (raw format)"),
			N_("net registry getvalueraw\n"
			   "    Print a registry value (raw format)")
		},
		{
			"setvalue",
			net_registry_setvalue,
			NET_TRANSPORT_LOCAL,
			N_("Set a new registry value"),
			N_("net registry setvalue\n"
			   "    Set a new registry value")
		},
		{
			"increment",
			net_registry_increment,
			NET_TRANSPORT_LOCAL,
			N_("Increment a DWORD registry value under a lock"),
			N_("net registry increment\n"
			   "    Increment a DWORD registry value under a lock")
		},
		{
			"deletevalue",
			net_registry_deletevalue,
			NET_TRANSPORT_LOCAL,
			N_("Delete a registry value"),
			N_("net registry deletevalue\n"
			   "    Delete a registry value")
		},
		{
			"getsd",
			net_registry_getsd,
			NET_TRANSPORT_LOCAL,
			N_("Get security descriptor"),
			N_("net registry getsd\n"
			   "    Get security descriptor")
		},
		{
			"getsd_sddl",
			net_registry_getsd_sddl,
			NET_TRANSPORT_LOCAL,
			N_("Get security descriptor in sddl format"),
			N_("net registry getsd_sddl\n"
			   "    Get security descriptor in sddl format")
		},
		{
			"setsd_sddl",
			net_registry_setsd_sddl,
			NET_TRANSPORT_LOCAL,
			N_("Set security descriptor from sddl format string"),
			N_("net registry setsd_sddl\n"
			   "    Set security descriptor from sddl format string")
		},
	{ NULL, NULL, 0, NULL, NULL }
	};

	if (!W_ERROR_IS_OK(registry_init_basic())) {
		return -1;
	}

	ret = net_run_function(c, argc, argv, "net registry", func);

	return ret;
}
