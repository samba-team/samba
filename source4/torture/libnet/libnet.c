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
	register_torture_op("NET-USERINFO", torture_userinfo, 0);
	register_torture_op("NET-USERADD", torture_useradd, 0);
	register_torture_op("NET-USERDEL", torture_userdel, 0);
	register_torture_op("NET-USERMOD", torture_usermod, 0);
	register_torture_op("NET-DOMOPEN", torture_domainopen, 0);
	register_torture_op("NET-API-LOOKUP", torture_lookup, 0);
	register_torture_op("NET-API-LOOKUPHOST", torture_lookup_host, 0);
	register_torture_op("NET-API-LOOKUPPDC", torture_lookup_pdc, 0);
	register_torture_op("NET-API-CREATEUSER", torture_createuser, 0);
	register_torture_op("NET-API-RPCCONNECT", torture_rpc_connect, 0);
	register_torture_op("NET-API-LISTSHARES", torture_listshares, 0);
	register_torture_op("NET-API-DELSHARE", torture_delshare, 0);

	return NT_STATUS_OK;
}
