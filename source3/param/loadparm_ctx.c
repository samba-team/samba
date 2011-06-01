#include "includes.h"
#include "../source4/param/s3_param.h"

/* These are in the order that they appear in the s4 loadparm file.
 * All of the s4 loadparm functions should be here eventually, once
 * they are implemented in the s3 loadparm, have the same format (enum
 * values in particular) and defaults. */
static const struct loadparm_s3_context s3_fns = 
{
	.server_role = lp_server_role,

	.winbind_separator = lp_winbind_separator,
	.template_homedir = lp_template_homedir,
	.template_shell = lp_template_shell,

	.dos_charset = lp_dos_charset,
	.unix_charset = lp_unix_charset,
	.display_charset = lp_display_charset,

	.realm = lp_realm,
	.dnsdomain = lp_dnsdomain,
	.socket_options = lp_socket_options,
	.workgroup = lp_workgroup,

	.netbios_name = global_myname,
	.netbios_scope = global_scope,

	.lanman_auth = lp_lanman_auth,
	.ntlm_auth = lp_ntlm_auth,

	.client_plaintext_auth = lp_client_plaintext_auth,
	.client_lanman_auth = lp_client_lanman_auth,
	.client_ntlmv2_auth = lp_client_ntlmv2_auth,

	.private_dir = lp_private_dir,
	.ncalrpc_dir = lp_ncalrpc_dir,
	.lockdir = lp_lockdir
};

const struct loadparm_s3_context *loadparm_s3_context(void)
{
	return &s3_fns;
}
