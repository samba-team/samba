/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald Carter                   2005.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "includes.h"
#include "rpc_client.h"

/*******************************************************************
*******************************************************************/

WERROR rpccli_svcctl_enumerate_services( struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx,
                                      POLICY_HND *hSCM, uint32 type, uint32 state, 
				      uint32 *returned, ENUM_SERVICES_STATUS **service_array  )
{
	SVCCTL_Q_ENUM_SERVICES_STATUS in;
	SVCCTL_R_ENUM_SERVICES_STATUS out;
	prs_struct qbuf, rbuf;
	uint32 resume = 0;
	ENUM_SERVICES_STATUS *services;
	int i;

	ZERO_STRUCT(in);
	ZERO_STRUCT(out);
	
	/* setup the request */
	
	memcpy( &in.handle, hSCM, sizeof(POLICY_HND) );
	
	in.type        = type;
	in.state       = state;
	in.resume      = &resume;
	
	/* first time is to get the buffer size */
	in.buffer_size = 0;

	CLI_DO_RPC_WERR( cli, mem_ctx, &ndr_table_svcctl.syntax_id, SVCCTL_ENUM_SERVICES_STATUS_W,
	            in, out, 
	            qbuf, rbuf,
	            svcctl_io_q_enum_services_status,
	            svcctl_io_r_enum_services_status, 
	            WERR_GENERAL_FAILURE );

	/* second time with correct buffer size...should be ok */
	
	if ( W_ERROR_EQUAL( out.status, WERR_MORE_DATA ) ) {
		in.buffer_size = out.needed;

		CLI_DO_RPC_WERR( cli, mem_ctx, &ndr_table_svcctl.syntax_id,
				 SVCCTL_ENUM_SERVICES_STATUS_W,
		            in, out, 
		            qbuf, rbuf,
		            svcctl_io_q_enum_services_status,
		            svcctl_io_r_enum_services_status, 
		            WERR_GENERAL_FAILURE );
	}
	
	if ( !W_ERROR_IS_OK(out.status) ) 
		return out.status;
		
	/* pull out the data */
	if (out.returned) {
		if ( !(services = TALLOC_ARRAY( mem_ctx, ENUM_SERVICES_STATUS, out.returned )) ) 
			return WERR_NOMEM;
	} else {
		services = NULL;
	}
		
	for ( i=0; i<out.returned; i++ ) {
		svcctl_io_enum_services_status( "", &services[i], &out.buffer, 0 );
	}
	
	*service_array = services;
	*returned      = out.returned;
	
	return out.status;
}
