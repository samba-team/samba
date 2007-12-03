/* 
   Unix SMB/CIFS implementation.
   RPC Pipe client
 
   Copyright (C) Gerald (Jerry) Carter        2005-2006
   
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
#include "rpc_client.h"

/*******************************************************************
 connect to a registry hive root (open a registry policy)
*******************************************************************/

NTSTATUS rpccli_winreg_Connect(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                         uint32 reg_type, uint32 access_mask,
                         POLICY_HND *reg_hnd)
{
	ZERO_STRUCTP(reg_hnd);

	switch (reg_type)
	{
	case HKEY_CLASSES_ROOT:
		return rpccli_winreg_OpenHKCR( cli, mem_ctx, NULL, 
			access_mask, reg_hnd, NULL);

	case HKEY_LOCAL_MACHINE:
		return rpccli_winreg_OpenHKLM( cli, mem_ctx, NULL, 
			access_mask, reg_hnd, NULL);

	case HKEY_USERS:
		return rpccli_winreg_OpenHKU( cli, mem_ctx, NULL, 
			access_mask, reg_hnd, NULL);

	case HKEY_CURRENT_USER:
		return rpccli_winreg_OpenHKCU( cli, mem_ctx, NULL, 
			access_mask, reg_hnd, NULL);

	case HKEY_PERFORMANCE_DATA:
		return rpccli_winreg_OpenHKPD( cli, mem_ctx, NULL, 
			access_mask, reg_hnd, NULL);

	default:
		/* fall through to end of function */
		break;
	}

	return NT_STATUS_INVALID_PARAMETER;
}

/*******************************************************************
 Fill in a REGVAL_BUFFER for the data given a REGISTRY_VALUE
 *******************************************************************/

uint32 reg_init_regval_buffer( REGVAL_BUFFER *buf2, REGISTRY_VALUE *val )
{
	uint32		real_size = 0;
	
	if ( !buf2 || !val )
		return 0;
		
	real_size = regval_size(val);
	init_regval_buffer( buf2, (unsigned char*)regval_data_p(val), real_size );

	return real_size;
}
