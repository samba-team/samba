/* 
   Unix SMB/CIFS implementation.

   libnet_BecomeDC() tests

   Copyright (C) Stefan (metze) Metzmacher 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/cmdline/popt_common.h"
#include "torture/torture.h"
#include "torture/rpc/rpc.h"
#include "libnet/libnet.h"
#include "lib/events/events.h"

#define TORTURE_NETBIOS_NAME "smbtorturedc"

static NTSTATUS test_become_dc_check_options(void *private_data,
					    const struct libnet_BecomeDC_CheckOptions *o)
{
	DEBUG(0,("Become DC of Domain[%s]/[%s]\n",
		o->domain->netbios_name, o->domain->dns_name));

	DEBUG(0,("Promotion Partner is Server[%s] from Site[%s]\n",
		o->source_dsa->dns_name, o->source_dsa->site_name));

	DEBUG(0,("Options:crossRef behavior_version[%u]\n"
		       "\tschema object_version[%u]\n"
		       "\tdomain behavior_version[%u]\n"
		       "\tdomain w2k3_update_revision[%u]\n", 
		o->forest->crossref_behavior_version,
		o->forest->schema_object_version,
		o->domain->behavior_version,
		o->domain->w2k3_update_revision));

	return NT_STATUS_OK;
}

BOOL torture_net_become_dc(struct torture_context *torture)
{
	BOOL ret = True;
	NTSTATUS status;
	struct libnet_context *ctx;
	struct libnet_BecomeDC b;
	struct libnet_UnbecomeDC u;
	struct test_join *tj;
	struct cli_credentials *machine_account;

	/* Join domain as a member server. */
	tj = torture_join_domain(TORTURE_NETBIOS_NAME,
				 ACB_WSTRUST,
				 &machine_account);
	if (!tj) {
		DEBUG(0, ("%s failed to join domain as workstation\n",
			  TORTURE_NETBIOS_NAME));
		return False;
	}

	ctx = libnet_context_init(event_context_init(torture));
	ctx->cred = cmdline_credentials;

	ZERO_STRUCT(b);
	b.in.domain_dns_name		= torture_join_dom_dns_name(tj);
	b.in.domain_netbios_name	= torture_join_dom_netbios_name(tj);
	b.in.domain_sid			= torture_join_sid(tj);
	b.in.source_dsa_address		= lp_parm_string(-1, "torture", "host");
	b.in.dest_dsa_netbios_name	= TORTURE_NETBIOS_NAME;

	b.in.callbacks.check_options	= test_become_dc_check_options;

	status = libnet_BecomeDC(ctx, ctx, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_BecomeDC() failed - %s\n", nt_errstr(status));
		ret = False;
	}

	ZERO_STRUCT(u);
	u.in.domain_dns_name		= torture_join_dom_dns_name(tj);
	u.in.domain_netbios_name	= torture_join_dom_netbios_name(tj);
	u.in.source_dsa_address		= lp_parm_string(-1, "torture", "host");
	u.in.dest_dsa_netbios_name	= TORTURE_NETBIOS_NAME;

	status = libnet_UnbecomeDC(ctx, ctx, &u);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_UnbecomeDC() failed - %s\n", nt_errstr(status));
		ret = False;
	}

	/* Leave domain. */                          
	torture_leave_domain(tj);
	
	return ret;
}
