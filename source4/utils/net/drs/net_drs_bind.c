/*
   Unix SMB/CIFS implementation.

   Implements functions offered by repadmin.exe tool under Windows

   Copyright (C) Kamen Mazdrashki <kamen.mazdrashki@postpath.com> 2010

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
#include "utils/net/net.h"
#include "utils/net/drs/net_drs.h"


#define DEFINE_FLAG(_flag, _win_name) {_flag, #_flag, _win_name}

struct drs_extension_flag {
	uint32_t 	flag;
	const char 	*samba_name;
	const char 	*win_name;
};

static const struct drs_extension_flag drs_repl_flags[] = {
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_BASE, 			"DRS_EXT_BASE"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION, 	"DRS_EXT_ASYNCREPL"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI, 		"DRS_EXT_REMOVEAPI"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2,		"DRS_EXT_MOVEREQ_V2"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS,	"DRS_EXT_GETCHG_DEFLATE"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1,		"DRS_EXT_DCINFO_V1"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION, "DRS_EXT_RESTORE_USN_OPTIMIZATION"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY,		"DRS_EXT_ADDENTRY"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE,		"DRS_EXT_KCC_EXECUTE"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2,		"DRS_EXT_ADDENTRY_V2"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION, "DRS_EXT_LINKED_VALUE_REPLICATION"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2,		"DRS_EXT_DCINFO_V2"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD, "DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND,		"DRS_EXT_CRYPTO_BIND"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO,		"DRS_EXT_GET_REPL_INFO"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION,	"DRS_EXT_STRONG_ENCRYPTION"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01,		"DRS_EXT_DCINFO_VFFFFFFFF"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP,	"DRS_EXT_TRANSITIVE_MEMBERSHIP"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY,	"DRS_EXT_ADD_SID_HISTORY"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3,		"DRS_EXT_POST_BETA3"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V5,		"DRS_EXT_GETCHGREQ_V5"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2,	"DRS_EXT_GETMEMBERSHIPS2"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6,		"DRS_EXT_GETCHGREQ_V6"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS,		"DRS_EXT_NONDOMAIN_NCS"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8,		"DRS_EXT_GETCHGREQ_V8"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5,		"DRS_EXT_GETCHGREPLY_V5"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6,		"DRS_EXT_GETCHGREPLY_V6"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3,	"DRS_EXT_WHISTLER_BETA3"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7,		"DRS_EXT_WHISTLER_BETA3"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT,		"DRS_EXT_WHISTLER_BETA3"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_XPRESS_COMPRESS,	"DRS_EXT_W2K3_DEFLATE"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V10,		"DRS_EXT_GETCHGREQ_V10"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_RESERVED_PART2,		"DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_RESERVED_PART3,		"DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3")
};

static const struct drs_extension_flag drs_repl_flags_ex[] = {
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_ADAM,			"DRS_EXT_ADAM"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_LH_BETA2,		"DRS_EXT_LH_BETA2"),
	DEFINE_FLAG(DRSUAPI_SUPPORTED_EXTENSION_RECYCLE_BIN,		"DRS_EXT_RECYCLE_BIN")
};



int net_drs_bind_cmd(struct net_context *ctx, int argc, const char **argv)
{
	int i;
	struct net_drs_context *drs_ctx;
	struct drsuapi_DsBindInfo48 *info48;

	/* only one arg expected */
	if (argc != 1) {
		return net_drs_bind_usage(ctx, argc, argv);
	}

	if (!net_drs_create_context(ctx, argv[0], &drs_ctx)) {
		return -1;
	}

	d_printf("Bind to %s succeeded.\n", drs_ctx->dc_name);
	d_printf("Extensions supported (cb=%d):\n", drs_ctx->drs_conn->bind_info_len);

	/* Print standard flags */
	info48 = &drs_ctx->drs_conn->info48;
	for (i = 0; i < ARRAY_SIZE(drs_repl_flags); i++) {
		const struct drs_extension_flag *repl_flag = &drs_repl_flags[i];
		d_printf("  %-60s: %-3s (%s)\n", repl_flag->samba_name,
		         info48->supported_extensions & repl_flag->flag ? "Yes" : "No",
		         repl_flag->win_name);
	}

	/* Print Extended flags */
	d_printf("\n");
	d_printf("Extended Extensions supported:\n");
	for (i = 0; i < ARRAY_SIZE(drs_repl_flags_ex); i++) {
		const struct drs_extension_flag *repl_flag_ex = &drs_repl_flags_ex[i];
		d_printf("  %-60s: %-3s (%s)\n", repl_flag_ex->samba_name,
			 info48->supported_extensions_ext & repl_flag_ex->flag ? "Yes" : "No",
			 repl_flag_ex->win_name);
	}

	/* print additional info */
	d_printf("\n");
	d_printf("Site GUID:   %s\n", GUID_string(drs_ctx, &info48->site_guid));
	d_printf("Repl epoch:  %d\n", info48->repl_epoch);
	if (GUID_all_zero(&info48->config_dn_guid)) {
		d_printf("Forest GUID: (none)\n");
	} else {
		d_printf("Forest GUID: %s\n", GUID_string(drs_ctx, &info48->config_dn_guid));
	}

	talloc_free(drs_ctx);

	return 0;
}

int net_drs_bind_usage(struct net_context *ctx, int argc, const char **argv)
{
	d_printf("net drs bind <DC_NAME>\n");
	return 0;
}
