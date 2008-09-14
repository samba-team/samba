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

/* dump sam database via samsync rpc calls */
NTSTATUS rpc_samdump_internals(struct net_context *c,
				const DOM_SID *domain_sid,
				const char *domain_name,
				struct cli_state *cli,
				struct rpc_pipe_client *pipe_hnd,
				TALLOC_CTX *mem_ctx,
				int argc,
				const char **argv)
{
	struct samsync_context *ctx = NULL;
	NTSTATUS status;

	status = libnet_samsync_init_context(mem_ctx,
					     domain_sid,
					     &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ctx->mode		= NET_SAMSYNC_MODE_DUMP;
	ctx->cli		= pipe_hnd;
	ctx->delta_fn		= display_sam_entries;
	ctx->domain_name	= domain_name;

	libnet_samsync(SAM_DATABASE_DOMAIN, ctx);

	libnet_samsync(SAM_DATABASE_BUILTIN, ctx);

	libnet_samsync(SAM_DATABASE_PRIVS, ctx);

	TALLOC_FREE(ctx);

	return NT_STATUS_OK;
}

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
	d_printf("net rpc vampire ([ldif [<ldif-filename>] | [keytab] [<keytab-filename]) [options]\n"
		 "\t to pull accounts from a remote PDC where we are a BDC\n"
		 "\t\t no args puts accounts in local passdb from smb.conf\n"
		 "\t\t ldif - put accounts in ldif format (file defaults to "
		 "/tmp/tmp.ldif)\n"
		 "\t\t keytab - put account passwords in krb5 keytab (defaults "
		 "to system keytab)\n");

	net_common_flags_usage(c, argc, argv);
	return -1;
}


/* dump sam database via samsync rpc calls */
NTSTATUS rpc_vampire_internals(struct net_context *c,
				const DOM_SID *domain_sid,
				const char *domain_name,
				struct cli_state *cli,
				struct rpc_pipe_client *pipe_hnd,
				TALLOC_CTX *mem_ctx,
				int argc,
				const char **argv)
{
	NTSTATUS result;
	struct samsync_context *ctx = NULL;

	if (!sid_equal(domain_sid, get_global_sam_sid())) {
		d_printf("Cannot import users from %s at this time, "
			 "as the current domain:\n\t%s: %s\nconflicts "
			 "with the remote domain\n\t%s: %s\n"
			 "Perhaps you need to set: \n\n\tsecurity=user\n\t"
			 "workgroup=%s\n\n in your smb.conf?\n",
			 domain_name,
			 get_global_sam_name(),
			 sid_string_dbg(get_global_sam_sid()),
			 domain_name,
			 sid_string_dbg(domain_sid),
			 domain_name);
		return NT_STATUS_UNSUCCESSFUL;
	}

	result = libnet_samsync_init_context(mem_ctx,
					     domain_sid,
					     &ctx);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	ctx->mode		= NET_SAMSYNC_MODE_FETCH_PASSDB;
	ctx->cli		= pipe_hnd;
	ctx->delta_fn		= fetch_sam_entries;
	ctx->domain_name	= domain_name;

	/* fetch domain */
	result = libnet_samsync(SAM_DATABASE_DOMAIN, ctx);

	if (!NT_STATUS_IS_OK(result) && ctx->error_message) {
		d_fprintf(stderr, "%s\n", ctx->error_message);
		goto fail;
	}

	if (ctx->result_message) {
		d_fprintf(stdout, "%s\n", ctx->result_message);
	}

	/* fetch builtin */
	ctx->domain_sid = sid_dup_talloc(mem_ctx, &global_sid_Builtin);
	ctx->domain_sid_str = sid_string_talloc(mem_ctx, ctx->domain_sid);
	result = libnet_samsync(SAM_DATABASE_BUILTIN, ctx);

	if (!NT_STATUS_IS_OK(result) && ctx->error_message) {
		d_fprintf(stderr, "%s\n", ctx->error_message);
		goto fail;
	}

	if (ctx->result_message) {
		d_fprintf(stdout, "%s\n", ctx->result_message);
	}

 fail:
	TALLOC_FREE(ctx);
	return result;
}

NTSTATUS rpc_vampire_ldif_internals(struct net_context *c,
				    const DOM_SID *domain_sid,
				    const char *domain_name,
				    struct cli_state *cli,
				    struct rpc_pipe_client *pipe_hnd,
				    TALLOC_CTX *mem_ctx,
				    int argc,
				    const char **argv)
{
	NTSTATUS status;
	struct samsync_context *ctx = NULL;

	status = libnet_samsync_init_context(mem_ctx,
					     domain_sid,
					     &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (argc >= 1) {
		ctx->output_filename = argv[0];
	}

	ctx->mode		= NET_SAMSYNC_MODE_FETCH_LDIF;
	ctx->cli		= pipe_hnd;
	ctx->delta_fn		= fetch_sam_entries_ldif;
	ctx->domain_name	= domain_name;

	/* fetch domain */
	status = libnet_samsync(SAM_DATABASE_DOMAIN, ctx);

	if (!NT_STATUS_IS_OK(status) && ctx->error_message) {
		d_fprintf(stderr, "%s\n", ctx->error_message);
		goto fail;
	}

	if (ctx->result_message) {
		d_fprintf(stdout, "%s\n", ctx->result_message);
	}

	/* fetch builtin */
	ctx->domain_sid = sid_dup_talloc(mem_ctx, &global_sid_Builtin);
	ctx->domain_sid_str = sid_string_talloc(mem_ctx, ctx->domain_sid);
	status = libnet_samsync(SAM_DATABASE_BUILTIN, ctx);

	if (!NT_STATUS_IS_OK(status) && ctx->error_message) {
		d_fprintf(stderr, "%s\n", ctx->error_message);
		goto fail;
	}

	if (ctx->result_message) {
		d_fprintf(stdout, "%s\n", ctx->result_message);
	}

 fail:
	TALLOC_FREE(ctx);
	return status;
}

int rpc_vampire_ldif(struct net_context *c, int argc, const char **argv)
{
	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net rpc vampire ldif\n"
			 "    Dump remote SAM database to LDIF file or stdout\n");
		return 0;
	}

	return run_rpc_command(c, NULL, &ndr_table_netlogon.syntax_id, 0,
			       rpc_vampire_ldif_internals, argc, argv);
}


NTSTATUS rpc_vampire_keytab_internals(struct net_context *c,
				      const DOM_SID *domain_sid,
				      const char *domain_name,
				      struct cli_state *cli,
				      struct rpc_pipe_client *pipe_hnd,
				      TALLOC_CTX *mem_ctx,
				      int argc,
				      const char **argv)
{
	NTSTATUS status;
	struct samsync_context *ctx = NULL;

	status = libnet_samsync_init_context(mem_ctx,
					     domain_sid,
					     &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (argc >= 1) {
		ctx->output_filename = argv[0];
	}

	ctx->mode		= NET_SAMSYNC_MODE_FETCH_KEYTAB;
	ctx->cli		= pipe_hnd;
	ctx->delta_fn		= fetch_sam_entries_keytab;
	ctx->domain_name	= domain_name;
	ctx->username		= c->opt_user_name;
	ctx->password		= c->opt_password;

	/* fetch domain */
	status = libnet_samsync(SAM_DATABASE_DOMAIN, ctx);

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

static NTSTATUS rpc_vampire_keytab_ds_internals(struct net_context *c,
						const DOM_SID *domain_sid,
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

	if (argc >= 1) {
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

	if (c->display_usage) {
		d_printf("Usage:\n"
			 "net rpc vampire keytab\n"
			 "    Dump remote SAM database to Kerberos keytab file\n");
		return 0;
	}

	ret = run_rpc_command(c, NULL, &ndr_table_drsuapi.syntax_id,
			      NET_FLAGS_SEAL,
			      rpc_vampire_keytab_ds_internals, argc, argv);
	if (ret == 0) {
		return 0;
	}

	return run_rpc_command(c, NULL, &ndr_table_netlogon.syntax_id, 0,
			       rpc_vampire_keytab_internals,
			       argc, argv);
}
