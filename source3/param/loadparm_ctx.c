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
#include "lib/param/s3_param.h"

static struct loadparm_service *lp_service_for_s4_ctx(const char *servicename)
{
	TALLOC_CTX *mem_ctx;
	struct loadparm_service *service;

	mem_ctx = talloc_stackframe();
	service = lp_service(servicename);
	talloc_free(mem_ctx);

	return service;
}

static struct loadparm_service *lp_servicebynum_for_s4_ctx(int servicenum)
{
	TALLOC_CTX *mem_ctx;
	struct loadparm_service *service;

	mem_ctx = talloc_stackframe();
	service = lp_servicebynum(servicenum);
	talloc_free(mem_ctx);

	return service;
}

static bool lp_load_for_s4_ctx(const char *filename)
{
	TALLOC_CTX *mem_ctx;
	bool status;

	mem_ctx = talloc_stackframe();
	status =  lp_load(filename, false, false, false, false);
	talloc_free(mem_ctx);

	return status;
}

/* These are in the order that they appear in the s4 loadparm file.
 * All of the s4 loadparm functions should be here eventually, once
 * they are implemented in the s3 loadparm, have the same format (enum
 * values in particular) and defaults. */
static const struct loadparm_s3_helpers s3_fns =
{
	.get_parametric = lp_parm_const_string_service,
	.get_parm_struct = lp_get_parameter,
	.get_parm_ptr = lp_parm_ptr,
	.get_service = lp_service_for_s4_ctx,
	.get_servicebynum = lp_servicebynum_for_s4_ctx,
	.get_default_loadparm_service = lp_default_loadparm_service,
	.get_numservices = lp_numservices,
	.load = lp_load_for_s4_ctx,
	.set_cmdline = lp_set_cmdline,
	.dump = lp_dump,

	._server_role = lp__server_role,
	._security = lp__security,
	._domain_master = lp__domain_master,
	._domain_logons = lp__domain_logons,

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
	.client_use_spnego_principal = lp_client_use_spnego_principal,

	.private_dir = lp_private_dir,
	.ncalrpc_dir = lp_ncalrpc_dir,
	.lockdir = lp_lockdir,

	.passdb_backend = lp_passdb_backend,

	.host_msdfs = lp_host_msdfs,
	.unix_extensions = lp_unix_extensions,
	.use_spnego = lp_use_spnego,
	.use_mmap = lp_use_mmap,

	.srv_minprotocol = lp_srv_minprotocol,
	.srv_maxprotocol = lp_srv_maxprotocol,

	.passwordserver = lp_passwordserver
};

const struct loadparm_s3_helpers *loadparm_s3_helpers(void)
{
	return &s3_fns;
}
