/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon glue functions to connect new cli interface
   to older style lsa_ and samr_ functions

   Copyright (C) tridge@samba.org 2001
   
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

#include "winbindd.h"

/****************************************************************************
do a LSA Open Policy
****************************************************************************/
BOOL wb_lsa_open_policy(char *server, BOOL sec_qos, uint32 des_access,
		     CLI_POLICY_HND *pol)
{
	struct nmb_name calling, called;
	struct ntuser_creds creds;
	struct in_addr dest_ip;
	fstring dest_host;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	extern pstring global_myname;

	ZERO_STRUCTP(pol);

	pol->cli = (struct cli_state *)malloc(sizeof(struct cli_state));
	pol->mem_ctx = talloc_init();

	ZERO_STRUCTP(pol->cli);

	if (!pol->cli || !pol->mem_ctx)
		return False;

	/* Initialise RPC connection */

	if (!cli_initialise(pol->cli))
		goto done;

	ZERO_STRUCT(creds);
	creds.pwd.null_pwd = 1;

	cli_init_creds(pol->cli, &creds);

	/* Establish a SMB connection */

	if (!resolve_srv_name(server, dest_host, &dest_ip)) {
		goto done;
	}

	make_nmb_name(&called, dns_to_netbios_name(dest_host), 0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	if (!cli_establish_connection(pol->cli, dest_host, &dest_ip, &calling, 
				      &called, "IPC$", "IPC", False, True)) {
		goto done;
	}
	
	if (!cli_nt_session_open (pol->cli, PIPE_LSARPC)) {
		goto done;
	}

	result = cli_lsa_open_policy(pol->cli, pol->mem_ctx, sec_qos,
				     des_access, &pol->handle);

 done:
	if (result != NT_STATUS_NOPROBLEMO && pol->cli) {
		if (pol->cli->initialised)
			cli_shutdown(pol->cli);
		free(pol->cli);
	}

	return (result == NT_STATUS_NOPROBLEMO);
}

/****************************************************************************
do a LSA Enumerate Trusted Domain 
****************************************************************************/
BOOL wb_lsa_enum_trust_dom(CLI_POLICY_HND *hnd, uint32 *enum_ctx,
			   uint32 * num_doms, char ***names, DOM_SID **sids)
{
	uint32 ret;

	ret = cli_lsa_enum_trust_dom(hnd->cli, hnd->mem_ctx, &hnd->handle,
				     enum_ctx, num_doms, names, sids);

	return (ret == NT_STATUS_NOPROBLEMO);
}

/****************************************************************************
do a LSA Query Info Policy
****************************************************************************/
BOOL wb_lsa_query_info_pol(CLI_POLICY_HND *hnd, uint16 info_class,
			   fstring domain_name, DOM_SID *domain_sid)
{
	uint32 ret;

	ret = cli_lsa_query_info_policy(hnd->cli, hnd->mem_ctx, &hnd->handle,
					info_class, domain_name, domain_sid);

	return (ret == NT_STATUS_NOPROBLEMO);
}

/****************************************************************************
do a LSA Lookup Names
****************************************************************************/
BOOL wb_lsa_lookup_names(CLI_POLICY_HND *hnd, int num_names, char **names,
			 DOM_SID **sids, uint32 **types, int *num_sids)
{
	uint32 ret;

	ret = cli_lsa_lookup_names(hnd->cli, hnd->mem_ctx, &hnd->handle,
				   num_names, names, sids, types, num_sids);

	return (ret == NT_STATUS_NOPROBLEMO);
}

/****************************************************************************
do a LSA Lookup SIDS
****************************************************************************/
BOOL wb_lsa_lookup_sids(CLI_POLICY_HND *hnd, int num_sids, DOM_SID *sids,
			char ***names, uint32 **types, int *num_names)
{
	uint32 ret;

	ret = cli_lsa_lookup_sids(hnd->cli, hnd->mem_ctx, &hnd->handle,
				  num_sids, sids, names, types, num_names);

	return (ret == NT_STATUS_NOPROBLEMO);
}

/****************************************************************************
lsa_close glue
****************************************************************************/
BOOL wb_lsa_close(CLI_POLICY_HND *hnd)
{
	uint32 ret;

	ret = cli_lsa_close(hnd->cli, hnd->mem_ctx, &hnd->handle);

	return (ret == NT_STATUS_NOPROBLEMO);
}


/****************************************************************************
samr_close glue
****************************************************************************/
BOOL wb_samr_close(CLI_POLICY_HND *hnd)
{
	uint32 ret;

	ret = cli_samr_close(hnd->cli, hnd->mem_ctx, &hnd->handle);

	return (ret == NT_STATUS_NOPROBLEMO);
}


/****************************************************************************
samr_connect glue
****************************************************************************/
BOOL wb_samr_connect(char *server, uint32 access_mask, CLI_POLICY_HND *pol)
{
	struct nmb_name calling, called;
	struct ntuser_creds creds;
	struct in_addr dest_ip;
	fstring dest_host;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	extern pstring global_myname;

	ZERO_STRUCTP(pol);

	pol->cli = (struct cli_state *)malloc(sizeof(struct cli_state));

	ZERO_STRUCTP(pol->cli);

	pol->mem_ctx = talloc_init();

	if (!pol->cli || !pol->mem_ctx)
		return False;

	/* Initialise RPC connection */

	if (!cli_initialise(pol->cli))
		goto done;

	ZERO_STRUCT(creds);
	creds.pwd.null_pwd = 1;

	cli_init_creds(pol->cli, &creds);

	/* Establish a SMB connection */

	if (!resolve_srv_name(server, dest_host, &dest_ip)) {
		goto done;
	}

	make_nmb_name(&called, dns_to_netbios_name(dest_host), 0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	if (!cli_establish_connection(pol->cli, dest_host, &dest_ip, &calling, 
				      &called, "IPC$", "IPC", False, True)) {
		goto done;
	}
	
	if (!cli_nt_session_open (pol->cli, PIPE_SAMR)) {
		goto done;
	}

	result = cli_samr_connect(pol->cli, pol->mem_ctx, 
				  access_mask, &pol->handle);

 done:
	if (result != NT_STATUS_NOPROBLEMO && pol->cli) {
		if (pol->cli->initialised)
			cli_shutdown(pol->cli);
		free(pol->cli);
	}

	return (result == NT_STATUS_NOPROBLEMO);
}


/****************************************************************************
samr_open_domain glue
****************************************************************************/
BOOL wb_samr_open_domain(CLI_POLICY_HND *connect_pol, uint32 ace_perms,
			 DOM_SID *sid, CLI_POLICY_HND *domain_pol)
{
	uint32 ret;

	ret = cli_samr_open_domain(connect_pol->cli, 
				   connect_pol->mem_ctx,
				   &connect_pol->handle,
				   ace_perms,
				   sid,
				   &domain_pol->handle);

	if (ret == NT_STATUS_NOPROBLEMO) {
		domain_pol->cli = connect_pol->cli;
		domain_pol->mem_ctx = connect_pol->mem_ctx;
		return True;
	}

	return False;
}

/****************************************************************************
do a SAMR enumerate groups
****************************************************************************/
uint32 wb_samr_enum_dom_groups(CLI_POLICY_HND *pol, uint32 *start_idx, 
			       uint32 size, struct acct_info **sam,
			       uint32 *num_sam_groups)
{
	uint32 ret;

	ret = cli_samr_enum_dom_groups(pol->cli, pol->mem_ctx, &pol->handle,
				       start_idx, size, sam, num_sam_groups);

	return (ret == NT_STATUS_NOPROBLEMO);
}

/****************************************************************************
do a SAMR query userinfo
****************************************************************************/
BOOL wb_get_samr_query_userinfo(CLI_POLICY_HND *pol, uint32 info_level,
				uint32 user_rid, SAM_USERINFO_CTR **ctr)
{
	POLICY_HND user_pol;
	BOOL got_user_pol = False;
	uint32 result;

	if ((result = cli_samr_open_user(pol->cli, pol->mem_ctx, 
					 &pol->handle, MAXIMUM_ALLOWED_ACCESS,
					 user_rid, &user_pol)) 
	    != NT_STATUS_NOPROBLEMO)
		goto done;

	got_user_pol = True;

	if ((result = cli_samr_query_userinfo(pol->cli, pol->mem_ctx,
					      &user_pol, info_level, ctr))
	    != NT_STATUS_NOPROBLEMO)
		goto done;

 done:
	if (got_user_pol) cli_samr_close(pol->cli, pol->mem_ctx, &user_pol);

	return (result == NT_STATUS_NOPROBLEMO);
}

/****************************************************************************
do a SAMR enumerate groups
****************************************************************************/
BOOL wb_samr_open_user(CLI_POLICY_HND *pol, uint32 access_mask, uint32 rid,
		       POLICY_HND *user_pol)
{
	uint32 ret;

	ret = cli_samr_open_user(pol->cli, pol->mem_ctx, &pol->handle,
				 access_mask, rid, user_pol);

	return (ret == NT_STATUS_NOPROBLEMO);
}

BOOL wb_samr_query_usergroups(CLI_POLICY_HND *pol, uint32 *num_groups,
			      DOM_GID **gid)
{
	uint32 ret;

	ret = cli_samr_query_usergroups(pol->cli, pol->mem_ctx, &pol->handle,
					num_groups, gid);

	return (ret == NT_STATUS_NOPROBLEMO);
}

BOOL wb_get_samr_query_groupinfo(CLI_POLICY_HND *pol, uint32 info_level,
			      uint32 group_rid, GROUP_INFO_CTR *ctr)
{
	POLICY_HND group_pol;
	BOOL got_group_pol = False;
	uint32 result;

	if ((result = cli_samr_open_group(pol->cli, pol->mem_ctx,
					  &pol->handle, MAXIMUM_ALLOWED_ACCESS,
					  group_rid, &group_pol))
	    != NT_STATUS_NOPROBLEMO) 
		goto done;

	got_group_pol = True;

	if ((result = cli_samr_query_groupinfo(pol->cli, pol->mem_ctx,
					       &group_pol, info_level,
					       ctr)) != NT_STATUS_NOPROBLEMO)
		goto done;

 done:
	if (got_group_pol) cli_samr_close(pol->cli, pol->mem_ctx, &group_pol);

	return (result == NT_STATUS_NOPROBLEMO);
}

BOOL wb_sam_query_groupmem(CLI_POLICY_HND *pol, uint32 group_rid,
			   uint32 *num_names, uint32 **rid_mem, 
			   char ***names, uint32 **name_types)
{
	BOOL got_group_pol = False;
	POLICY_HND group_pol;
	uint32 result;

	if ((result = cli_samr_open_group(pol->cli, pol->mem_ctx,
					  &pol->handle, MAXIMUM_ALLOWED_ACCESS,
					  group_rid, &group_pol))
	    != NT_STATUS_NOPROBLEMO) 
		goto done;

	got_group_pol = True;

	if ((result = cli_samr_query_groupmem(pol->cli, pol->mem_ctx,
					      &group_pol, num_names, rid_mem, 
					      name_types))
	    != NT_STATUS_NOPROBLEMO)
		goto done;

	if ((result = cli_samr_lookup_rids(pol->cli, pol->mem_ctx,
					   &pol->handle, 1000, /* ??? */
					   *num_names, *rid_mem,
					   num_names, names, name_types))
	    != NT_STATUS_NOPROBLEMO)
		goto done;

 done:
	if (got_group_pol) cli_samr_close(pol->cli, pol->mem_ctx, &group_pol);

	return (result == NT_STATUS_NOPROBLEMO);	
}

BOOL wb_samr_query_dom_info(CLI_POLICY_HND *pol, uint16 switch_value,
			    SAM_UNK_CTR *ctr)
{
	uint32 ret;

	ret = cli_samr_query_dom_info(pol->cli, pol->mem_ctx, 
				      &pol->handle, switch_value, ctr);

	return (ret == NT_STATUS_NOPROBLEMO);
}

BOOL wb_samr_query_dispinfo(CLI_POLICY_HND *pol, uint32 *start_ndx, 
			    uint16 info_level, uint32 *num_entries,
			    SAM_DISPINFO_CTR *ctr)
{
	uint32 ret;

	ret = cli_samr_query_dispinfo(pol->cli, pol->mem_ctx, 
				      &pol->handle, start_ndx, info_level, 
				      num_entries, 0xffff, ctr);

	return (ret == NT_STATUS_NOPROBLEMO);
}
