/*
   Unix SMB/CIFS implementation.

   Winbind domain child functions

   Copyright (C) Stefan Metzmacher 2007

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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static const struct winbindd_child_dispatch_table domain_dispatch_table[];

void setup_domain_child(struct winbindd_domain *domain,
			struct winbindd_child *child)
{
	setup_child(child, domain_dispatch_table,
		    "log.wb", domain->name);

	child->domain = domain;
}

static const struct winbindd_child_dispatch_table domain_dispatch_table[] = {
	{
		.name		= "LOOKUPSID",
		.struct_cmd	= WINBINDD_LOOKUPSID,
		.struct_fn	= winbindd_dual_lookupsid,
	},{
		.name		= "LOOKUPNAME",
		.struct_cmd	= WINBINDD_LOOKUPNAME,
		.struct_fn	= winbindd_dual_lookupname,
	},{
		.name		= "LOOKUPRIDS",
		.struct_cmd	= WINBINDD_LOOKUPRIDS,
		.struct_fn	= winbindd_dual_lookuprids,
	},{
		.name		= "LIST_USERS",
		.struct_cmd	= WINBINDD_LIST_USERS,
		.struct_fn	= winbindd_dual_list_users,
	},{
		.name		= "LIST_GROUPS",
		.struct_cmd	= WINBINDD_LIST_GROUPS,
		.struct_fn	= winbindd_dual_list_groups,
	},{
		.name		= "LIST_TRUSTDOM",
		.struct_cmd	= WINBINDD_LIST_TRUSTDOM,
		.struct_fn	= winbindd_dual_list_trusted_domains,
	},{
		.name		= "INIT_CONNECTION",
		.struct_cmd	= WINBINDD_INIT_CONNECTION,
		.struct_fn	= winbindd_dual_init_connection,
	},{
		.name		= "GETDCNAME",
		.struct_cmd	= WINBINDD_GETDCNAME,
		.struct_fn	= winbindd_dual_getdcname,
	},{
		.name		= "SHOW_SEQUENCE",
		.struct_cmd	= WINBINDD_SHOW_SEQUENCE,
		.struct_fn	= winbindd_dual_show_sequence,
	},{
		.name		= "PAM_AUTH",
		.struct_cmd	= WINBINDD_PAM_AUTH,
		.struct_fn	= winbindd_dual_pam_auth,
	},{
		.name		= "AUTH_CRAP",
		.struct_cmd	= WINBINDD_PAM_AUTH_CRAP,
		.struct_fn	= winbindd_dual_pam_auth_crap,
	},{
		.name		= "PAM_LOGOFF",
		.struct_cmd	= WINBINDD_PAM_LOGOFF,
		.struct_fn	= winbindd_dual_pam_logoff,
	},{
		.name		= "CHNG_PSWD_AUTH_CRAP",
		.struct_cmd	= WINBINDD_PAM_CHNG_PSWD_AUTH_CRAP,
		.struct_fn	= winbindd_dual_pam_chng_pswd_auth_crap,
	},{
		.name		= "PAM_CHAUTHTOK",
		.struct_cmd	= WINBINDD_PAM_CHAUTHTOK,
		.struct_fn	= winbindd_dual_pam_chauthtok,
	},{
		.name		= "CHECK_MACHACC",
		.struct_cmd	= WINBINDD_CHECK_MACHACC,
		.struct_fn	= winbindd_dual_check_machine_acct,
	},{
		.name		= "DUAL_USERINFO",
		.struct_cmd	= WINBINDD_DUAL_USERINFO,
		.struct_fn	= winbindd_dual_userinfo,
	},{
		.name		= "GETUSERDOMGROUPS",
		.struct_cmd	= WINBINDD_GETUSERDOMGROUPS,
		.struct_fn	= winbindd_dual_getuserdomgroups,
	},{
		.name		= "GETSIDALIASES",
		.struct_cmd	= WINBINDD_DUAL_GETSIDALIASES,
		.struct_fn	= winbindd_dual_getsidaliases,
	},{
		.name		= "CCACHE_NTLM_AUTH",
		.struct_cmd	= WINBINDD_CCACHE_NTLMAUTH,
		.struct_fn	= winbindd_dual_ccache_ntlm_auth,
	},{
		.name		= NULL,
	}
};
