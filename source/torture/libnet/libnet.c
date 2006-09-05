/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Jelmer Vernooij 2006
   
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
#include "torture/torture.h"
#include "torture/libnet/proto.h"

NTSTATUS torture_net_init(void)
{
	register_torture_op("NET-USERINFO", torture_userinfo);
	register_torture_op("NET-USERADD", torture_useradd);
	register_torture_op("NET-USERDEL", torture_userdel);
	register_torture_op("NET-USERMOD", torture_usermod);
	register_torture_op("NET-DOMOPEN", torture_domainopen);
	register_torture_op("NET-API-LOOKUP", torture_lookup);
	register_torture_op("NET-API-LOOKUPHOST", torture_lookup_host);
	register_torture_op("NET-API-LOOKUPPDC", torture_lookup_pdc);
	register_torture_op("NET-API-LOOKUPNAME", torture_lookup_sam_name);
	register_torture_op("NET-API-CREATEUSER", torture_createuser);
	register_torture_op("NET-API-DELETEUSER", torture_deleteuser);
	register_torture_op("NET-API-MODIFYUSER", torture_modifyuser);
	register_torture_op("NET-API-USERINFO", torture_userinfo_api);
	register_torture_op("NET-API-RPCCONN-BIND", torture_rpc_connect_binding);
	register_torture_op("NET-API-RPCCONN-SRV", torture_rpc_connect_srv);
	register_torture_op("NET-API-RPCCONN-PDC", torture_rpc_connect_pdc);
	register_torture_op("NET-API-RPCCONN-DC", torture_rpc_connect_dc);
	register_torture_op("NET-API-RPCCONN-DCINFO", torture_rpc_connect_dc_info);
	register_torture_op("NET-API-LISTSHARES", torture_listshares);
	register_torture_op("NET-API-DELSHARE", torture_delshare);
	register_torture_op("NET-API-DOMOPENLSA", torture_domain_open_lsa);
	register_torture_op("NET-API-DOMCLOSELSA", torture_domain_close_lsa);
	register_torture_op("NET-API-DOMOPENSAMR", torture_domain_open_samr);
	register_torture_op("NET-API-DOMCLOSESAMR", torture_domain_close_samr);

	return NT_STATUS_OK;
}
