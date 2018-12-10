/*
   Unix SMB/CIFS implementation.
   dump the remote SAM using rpc samsync operations

   Copyright (C) Andrew Tridgell 2002
   Copyright (C) Tim Potter 2001,2002
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2005
   Modified by Volker Lendecke 2002
   Copyright (C) Jeremy Allison 2005.
   Copyright (C) Guenther Deschner 2008.

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
#include "utils/net.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "../librpc/gen_ndr/ndr_drsuapi.h"
#include "libnet/libnet_dssync.h"
#include "../libcli/security/security.h"
#include "passdb/machine_sid.h"

/**
 * Basic usage function for 'net rpc vampire'
 *
 * @param c	A net_context structure
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int rpc_vampire_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("net rpc vampire ([ldif [<ldif-filename>] | [keytab] "
		   "[<keytab-filename]) [options]\n"
		   "\t to pull accounts from a remote PDC where we are a BDC\n"
		   "\t\t no args puts accounts in local passdb from smb.conf\n"
		   "\t\t ldif - put accounts in ldif format (file defaults to "
		   "/tmp/tmp.ldif)\n"
		   "\t\t keytab - put account passwords in krb5 keytab "
		   "(defaults to system keytab)\n"));

	net_common_flags_usage(c, argc, argv);
	return -1;
}

static NTSTATUS rpc_vampire_ds_internals(struct net_context *c,
					 const struct dom_sid *domain_sid,
					 const char *domain_name,
					 struct cli_state *cli,
					 struct rpc_pipe_client *pipe_hnd,
					 TALLOC_CTX *mem_ctx,
					 int argc,
					 const char **argv)
{
	NTSTATUS status;
	struct dssync_context *ctx = NULL;

	if (!dom_sid_equal(domain_sid, get_global_sam_sid())) {
		struct dom_sid_buf buf1, buf2;
		d_printf(_("Cannot import users from %s at this time, "
			   "as the current domain:\n\t%s: %s\nconflicts "
			   "with the remote domain\n\t%s: %s\n"
			   "Perhaps you need to set: \n\n\tsecurity=user\n\t"
			   "workgroup=%s\n\n in your smb.conf?\n"),
			 domain_name,
			 get_global_sam_name(),
			 dom_sid_str_buf(get_global_sam_sid(), &buf1),
			 domain_name,
			 dom_sid_str_buf(domain_sid, &buf2),
			 domain_name);
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = libnet_dssync_init_context(mem_ctx,
					    &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ctx->cli		= pipe_hnd;
	ctx->domain_name	= domain_name;
	ctx->ops		= &libnet_dssync_passdb_ops;

	status = libnet_dssync(mem_ctx, ctx);
	if (!NT_STATUS_IS_OK(status) && ctx->error_message) {
		d_fprintf(stderr, "%s\n", ctx->error_message);
		goto out;
	}

	if (ctx->result_message) {
		d_fprintf(stdout, "%s\n", ctx->result_message);
	}

 out:
	TALLOC_FREE(ctx);

	return status;
}

int rpc_vampire_passdb(struct net_context *c, int argc, const char **argv)
{
	int ret = 0;
	NTSTATUS status;
	struct cli_state *cli = NULL;
	struct net_dc_info dc_info;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net rpc vampire passdb\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Dump remote SAM database to passdb"));
		return 0;
	}

	status = net_make_ipc_connection(c, 0, &cli);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	status = net_scan_dc(c, cli, &dc_info);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	if (!dc_info.is_ad) {
		printf(_("DC is not running Active Directory, exiting\n"));
		return -1;
	}

	if (!c->opt_force) {
		d_printf(  "%s\n"
			   "net rpc vampire passdb\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Should not be used against Active Directory, maybe use --force"));
		return -1;
	}

	ret = run_rpc_command(c, cli, &ndr_table_drsuapi,
			      NET_FLAGS_SEAL | NET_FLAGS_TCP,
			      rpc_vampire_ds_internals, argc, argv);
	return ret;
}

static NTSTATUS rpc_vampire_keytab_ds_internals(struct net_context *c,
						const struct dom_sid *domain_sid,
						const char *domain_name,
						struct cli_state *cli,
						struct rpc_pipe_client *pipe_hnd,
						TALLOC_CTX *mem_ctx,
						int argc,
						const char **argv)
{
	NTSTATUS status;
	struct dssync_context *ctx = NULL;

	status = libnet_dssync_init_context(mem_ctx,
					    &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ctx->force_full_replication = c->opt_force_full_repl ? true : false;
	ctx->clean_old_entries = c->opt_clean_old_entries ? true : false;

	if (argc < 1) {
		/* the caller should ensure that a filename is provided */
		return NT_STATUS_INVALID_PARAMETER;
	} else {
		ctx->output_filename = argv[0];
	}

	if (argc >= 2) {
		ctx->object_dns = &argv[1];
		ctx->object_count = argc - 1;
		ctx->single_object_replication = c->opt_single_obj_repl ? true
									: false;
	}

	ctx->cli		= pipe_hnd;
	ctx->domain_name	= domain_name;
	ctx->ops		= &libnet_dssync_keytab_ops;

	status = libnet_dssync(mem_ctx, ctx);
	if (!NT_STATUS_IS_OK(status) && ctx->error_message) {
		d_fprintf(stderr, "%s\n", ctx->error_message);
		goto out;
	}

	if (ctx->result_message) {
		d_fprintf(stdout, "%s\n", ctx->result_message);
	}

 out:
	TALLOC_FREE(ctx);

	return status;
}

/**
 * Basic function for 'net rpc vampire keytab'
 *
 * @param c	A net_context structure
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int rpc_vampire_keytab(struct net_context *c, int argc, const char **argv)
{
	int ret = 0;
	NTSTATUS status;
	struct cli_state *cli = NULL;
	struct net_dc_info dc_info;

	if (c->display_usage || (argc < 1)) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net rpc vampire keytab <keytabfile>\n"
			   "    Dump remote SAM database to Kerberos keytab "
			   "file\n"));
		return 0;
	}

	status = net_make_ipc_connection(c, 0, &cli);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	status = net_scan_dc(c, cli, &dc_info);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	if (!dc_info.is_ad) {
		printf(_("DC is not running Active Directory, exiting\n"));
		return -1;
	}

	ret = run_rpc_command(c, cli, &ndr_table_drsuapi,
			      NET_FLAGS_SEAL | NET_FLAGS_TCP,
			      rpc_vampire_keytab_ds_internals, argc, argv);
	return ret;
}
