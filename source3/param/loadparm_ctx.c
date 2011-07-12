/* 
   Unix SMB/CIFS implementation.
   Parameter loading functions
   Copyright (C) Andrew Bartlett 2011

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
#include "../source4/param/s3_param.h"

/* These are in the order that they appear in the s4 loadparm file.
 * All of the s4 loadparm functions should be here eventually, once
 * they are implemented in the s3 loadparm, have the same format (enum
 * values in particular) and defaults. */
static const struct loadparm_s3_context s3_fns = 
{
	.get_parametric = lp_parm_const_string_service,
	.get_parm_struct = lp_get_parameter,
	.get_parm_ptr = lp_parm_ptr,
	.get_service = lp_service,

	.server_role = lp_server_role,

	.winbind_separator = lp_winbind_separator,
	.template_homedir = lp_template_homedir,
	.template_shell = lp_template_shell,

	.dos_charset = lp_dos_charset,
	.unix_charset = lp_unix_charset,

	.realm = lp_realm,
	.dnsdomain = lp_dnsdomain,
	.socket_options = lp_socket_options,
	.workgroup = lp_workgroup,

	.netbios_name = lp_netbios_name,
	.netbios_scope = lp_netbios_scope,
	.netbios_aliases = lp_netbios_aliases,

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
