/* 
   Unix SMB/CIFS implementation.

   Convert a server info struct into the form for PAC and NETLOGON replies

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   Copyright (C) Stefan Metzmacher <metze@samba.org>  2005
   
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
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "auth/auth.h"
#include "lib/ldb/include/ldb.h"

NTSTATUS auth_convert_server_info_sambaseinfo(TALLOC_CTX *mem_ctx, 
					      struct auth_serversupplied_info *server_info, 
					      struct netr_SamBaseInfo **_sam)
{
	struct netr_SamBaseInfo *sam = talloc_zero(mem_ctx, struct netr_SamBaseInfo);
	NT_STATUS_HAVE_NO_MEMORY(sam);

	sam->last_logon = server_info->last_logon;
	sam->last_logoff = server_info->last_logoff;
	sam->acct_expiry = server_info->acct_expiry;
	sam->last_password_change = server_info->last_password_change;
	sam->allow_password_change = server_info->allow_password_change;
	sam->force_password_change = server_info->force_password_change;

	sam->account_name.string = server_info->account_name;
	sam->full_name.string = server_info->full_name;
	sam->logon_script.string = server_info->logon_script;
	sam->profile_path.string = server_info->profile_path;
	sam->home_directory.string = server_info->home_directory;
	sam->home_drive.string = server_info->home_drive;

	sam->logon_count = server_info->logon_count;
	sam->bad_password_count = sam->bad_password_count;
	sam->rid = server_info->account_sid->sub_auths[server_info->account_sid->num_auths-1];
	sam->primary_gid = server_info->primary_group_sid->sub_auths[server_info->primary_group_sid->num_auths-1];

	sam->groups.count = 0;
	sam->groups.rids = NULL;

	if (server_info->n_domain_groups > 0) {
		int i;
		sam->groups.rids = talloc_array(sam, struct samr_RidWithAttribute,
						server_info->n_domain_groups);

		if (sam->groups.rids == NULL)
			return NT_STATUS_NO_MEMORY;

		for (i=0; i<server_info->n_domain_groups; i++) {
			
			struct dom_sid *group_sid = server_info->domain_groups[i];
			sam->groups.rids[sam->groups.count].rid =
				group_sid->sub_auths[group_sid->num_auths-1];
			
			sam->groups.rids[sam->groups.count].attributes = 
				SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
			sam->groups.count += 1;
		}
	}

	sam->user_flags = 0; /* TODO: w2k3 uses 0x120.  We know 0x20
			      * as extra sids (PAC doc) but what is
			      * 0x100? */
	sam->acct_flags = server_info->acct_flags;
	sam->logon_server.string = lp_netbios_name();
	sam->domain.string = server_info->domain_name;

	sam->domain_sid = dom_sid_dup(mem_ctx, server_info->account_sid);
	NT_STATUS_HAVE_NO_MEMORY(sam->domain_sid);
	sam->domain_sid->num_auths--;

	ZERO_STRUCT(sam->unknown);

	ZERO_STRUCT(sam->key);
	if (server_info->user_session_key.length == sizeof(sam->key.key)) {
		memcpy(sam->key.key, server_info->user_session_key.data, sizeof(sam->key.key));
	}

	ZERO_STRUCT(sam->LMSessKey);
	if (server_info->lm_session_key.length == sizeof(sam->LMSessKey.key)) {
		memcpy(sam->LMSessKey.key, server_info->lm_session_key.data, 
		       sizeof(sam->LMSessKey.key));
	}
	
	*_sam = sam;

	return NT_STATUS_OK;
}	

