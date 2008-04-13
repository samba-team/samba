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
#include "utils/net.h"
#include "utils/net_registry_util.h"


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
		d_fprintf(stderr, "open_hive failed: %s\n", dos_errstr(werr));
		goto done;
	}

	werr = reg_openkey(ctx, hive, subkey_name, desired_access, key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "reg_openkey failed: %s\n",
			  dos_errstr(werr));
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

static int net_registry_enumerate(int argc, const char **argv)
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

	if (argc != 1) {
		d_printf("Usage:    net registry enumerate <path>\n");
		d_printf("Example:  net registry enumerate "
			 "'HKLM\\Software\\Samba'\n");
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_key failed: %s\n", dos_errstr(werr));
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

static int net_registry_createkey(int argc, const char **argv)
{
	WERROR werr;
	enum winreg_CreateAction action;
	char *subkeyname;
	struct registry_key *hivekey = NULL;
	struct registry_key *subkey = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 1) {
		d_printf("Usage:    net registry createkey <path>\n");
		d_printf("Example:  net registry createkey "
			 "'HKLM\\Software\\Samba\\smbconf.127.0.0.1'\n");
		goto done;
	}
	if (strlen(argv[0]) == 0) {
		d_fprintf(stderr, "error: zero length key name given\n");
		goto done;
	}

	werr = open_hive(ctx, argv[0], REG_KEY_WRITE, &hivekey, &subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_hive failed: %s\n", dos_errstr(werr));
		goto done;
	}

	werr = reg_createkey(ctx, hivekey, subkeyname, REG_KEY_WRITE,
			     &subkey, &action);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "reg_createkey failed: %s\n",
			  dos_errstr(werr));
		goto done;
	}
	switch (action) {
		case REG_ACTION_NONE:
			d_printf("createkey did nothing -- huh?\n");
			break;
		case REG_CREATED_NEW_KEY:
			d_printf("createkey created %s\n", argv[0]);
			break;
		case REG_OPENED_EXISTING_KEY:
			d_printf("createkey opened existing %s\n", argv[0]);
			break;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_deletekey(int argc, const char **argv)
{
	WERROR werr;
	char *subkeyname;
	struct registry_key *hivekey = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 1) {
		d_printf("Usage:    net registry deletekey <path>\n");
		d_printf("Example:  net registry deletekey "
			 "'HKLM\\Software\\Samba\\smbconf.127.0.0.1'\n");
		goto done;
	}
	if (strlen(argv[0]) == 0) {
		d_fprintf(stderr, "error: zero length key name given\n");
		goto done;
	}

	werr = open_hive(ctx, argv[0], REG_KEY_WRITE, &hivekey, &subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_hive failed: %s\n", dos_errstr(werr));
		goto done;
	}

	werr = reg_deletekey(hivekey, subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "reg_deletekey failed: %s\n",
			  dos_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_getvalue(int argc, const char **argv)
{
	WERROR werr;
	int ret = -1;
	struct registry_key *key = NULL;
	struct registry_value *value = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc != 2) {
		d_fprintf(stderr, "usage: net rpc registry getvalue <key> "
				  "<valuename>\n");
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_key failed: %s\n", dos_errstr(werr));
		goto done;
	}

	werr = reg_queryvalue(ctx, key, argv[1], &value);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "reg_queryvalue failed: %s\n",
			  dos_errstr(werr));
		goto done;
	}

	print_registry_value(value);

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_setvalue(int argc, const char **argv)
{
	WERROR werr;
	struct registry_value value;
	struct registry_key *key = NULL;
	int ret = -1;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc < 4) {
		d_fprintf(stderr, "usage: net rpc registry setvalue <key> "
			  "<valuename> <type> [<val>]+\n");
		goto done;
	}

	if (!strequal(argv[2], "multi_sz") && (argc != 4)) {
		d_fprintf(stderr, "Too many args for type %s\n", argv[2]);
		goto done;
	}

	if (strequal(argv[2], "dword")) {
		value.type = REG_DWORD;
		value.v.dword = strtoul(argv[3], NULL, 10);
	} else if (strequal(argv[2], "sz")) {
		value.type = REG_SZ;
		value.v.sz.len = strlen(argv[3])+1;
		value.v.sz.str = CONST_DISCARD(char *, argv[3]);
	} else {
		d_fprintf(stderr, "type \"%s\" not implemented\n", argv[2]);
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_key failed: %s\n", dos_errstr(werr));
		goto done;
	}

	werr = reg_setvalue(key, argv[1], &value);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "reg_setvalue failed: %s\n",
			  dos_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_deletevalue(int argc, const char **argv)
{
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 2) {
		d_fprintf(stderr, "usage: net rpc registry deletevalue <key> "
			  "<valuename>\n");
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_key failed: %s\n", dos_errstr(werr));
		goto done;
	}

	werr = reg_deletevalue(key, argv[1]);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "reg_deletekey failed: %s\n",
			  dos_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_getsd(int argc, const char **argv)
{
	WERROR werr;
	int ret = -1;
	struct registry_key *key = NULL;
	struct security_descriptor *secdesc = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	uint32_t access_mask = REG_KEY_READ |
			       SEC_RIGHT_MAXIMUM_ALLOWED |
			       SEC_RIGHT_SYSTEM_SECURITY;

	/*
	 * net_rpc_regsitry uses SEC_RIGHT_SYSTEM_SECURITY, but access
	 * is denied with these perms right now...
	 */
	access_mask = REG_KEY_READ;

	if (argc != 1) {
		d_printf("Usage:    net registry getsd <path>\n");
		d_printf("Example:  net registry getsd "
			 "'HKLM\\Software\\Samba'\n");
		goto done;
	}
	if (strlen(argv[0]) == 0) {
		d_fprintf(stderr, "error: zero length key name given\n");
		goto done;
	}

	werr = open_key(ctx, argv[0], access_mask, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_key failed: %s\n", dos_errstr(werr));
		goto done;
	}

	werr = reg_getkeysecurity(ctx, key, &secdesc);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "reg_getkeysecurity failed: %s\n",
			  dos_errstr(werr));
		goto done;
	}

	display_sec_desc(secdesc);

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

int net_registry(int argc, const char **argv)
{
	int ret = -1;

	struct functable2 func[] = {
		{
			"enumerate",
			net_registry_enumerate,
			"Enumerate registry keys and values"
		},
		{
			"createkey",
			net_registry_createkey,
			"Create a new registry key"
		},
		{
			"deletekey",
			net_registry_deletekey,
			"Delete a registry key"
		},
		{
			"getvalue",
			net_registry_getvalue,
			"Print a registry value",
		},
		{
			"setvalue",
			net_registry_setvalue,
			"Set a new registry value"
		},
		{
			"deletevalue",
			net_registry_deletevalue,
			"Delete a registry value"
		},
		{
			"getsd",
			net_registry_getsd,
			"Get security descriptor"
		},
	{ NULL, NULL, NULL }
	};

	if (!W_ERROR_IS_OK(registry_init_basic())) {
		return -1;
	}

	ret = net_run_function2(argc, argv, "net registry", func);

	return ret;
}
