/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald Carter                   2005.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"
#include "rpc_client.h"

/********************************************************************
********************************************************************/

WERROR cli_svcctl_open_scm( struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                              POLICY_HND *hSCM, uint32 access_desired )
{
	SVCCTL_Q_OPEN_SCMANAGER in;
	SVCCTL_R_OPEN_SCMANAGER out;
	prs_struct qbuf, rbuf;
	fstring server;
	
	ZERO_STRUCT(in);
	ZERO_STRUCT(out);
	
	/* leave the database name NULL to get the default service db */

	in.database = NULL;

	/* set the server name */

	if ( !(in.servername = TALLOC_P( mem_ctx, UNISTR2 )) )
		return WERR_NOMEM;
	fstr_sprintf( server, "\\\\%s", cli->desthost );
	init_unistr2( in.servername, server, UNI_STR_TERMINATE );

	in.access = access_desired;
	
	CLI_DO_RPC( cli, mem_ctx, PI_SVCCTL, SVCCTL_OPEN_SCMANAGER_W, 
	            in, out, 
	            qbuf, rbuf,
	            svcctl_io_q_open_scmanager,
	            svcctl_io_r_open_scmanager, 
	            WERR_GENERAL_FAILURE );
	
	if ( !W_ERROR_IS_OK( out.status ) )
		return out.status;

	memcpy( hSCM, &out.handle, sizeof(POLICY_HND) );
	
	return out.status;
}

/********************************************************************
********************************************************************/

WERROR close_service_handle( struct cli_state *cli, TALLOC_CTX *mem_ctx, POLICY_HND *hService )
{
	SVCCTL_Q_CLOSE_SERVICE in;
	SVCCTL_R_CLOSE_SERVICE out;
	prs_struct qbuf, rbuf;
	
	ZERO_STRUCT(in);
	ZERO_STRUCT(out);
	
	memcpy( &in.handle, hService, sizeof(POLICY_HND) );
	
	CLI_DO_RPC( cli, mem_ctx, PI_SVCCTL, SVCCTL_CLOSE_SERVICE, 
	            in, out, 
	            qbuf, rbuf,
	            svcctl_io_q_close_service,
	            svcctl_io_r_close_service, 
	            WERR_GENERAL_FAILURE );

	return out.status;
}

/*******************************************************************
*******************************************************************/

WERROR cli_svcctl_enumerate_services( struct cli_state *cli, TALLOC_CTX *mem_ctx,
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

	CLI_DO_RPC( cli, mem_ctx, PI_SVCCTL, SVCCTL_ENUM_SERVICES_STATUS_W, 
	            in, out, 
	            qbuf, rbuf,
	            svcctl_io_q_enum_services_status,
	            svcctl_io_r_enum_services_status, 
	            WERR_GENERAL_FAILURE );

	/* second time with correct buffer size...should be ok */
	
	if ( !W_ERROR_EQUAL( out.status, WERR_INSUFFICIENT_BUFFER ) ) {
		in.buffer_size = out.needed;

		CLI_DO_RPC( cli, mem_ctx, PI_SVCCTL, SVCCTL_ENUM_SERVICES_STATUS_W, 
		            in, out, 
		            qbuf, rbuf,
		            svcctl_io_q_enum_services_status,
		            svcctl_io_r_enum_services_status, 
		            WERR_GENERAL_FAILURE );
	}
	
	if ( !W_ERROR_IS_OK(out.status) ) 
		return out.status;
		
	/* pull out the data */
	if ( !(services = TALLOC_ARRAY( mem_ctx, ENUM_SERVICES_STATUS, out.returned )) ) 
		return WERR_NOMEM;
		
	for ( i=0; i<out.returned; i++ ) {
		svcctl_io_enum_services_status( "", &services[i], &out.buffer, 0 );
	}
	
	*service_array = services;
	*returned      = out.returned;
	
	

	return out.status;
}

/*******************************************************************
*******************************************************************/

WERROR cli_svcctl_start_service(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return WERR_OK;
}

/*******************************************************************
*******************************************************************/

WERROR cli_svcctl_control_service(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return WERR_OK;
}

/*******************************************************************
*******************************************************************/

WERROR cli_svcctl_query_status(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return WERR_OK;
}

/*******************************************************************
*******************************************************************/

WERROR cli_svcctl_query_config(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return WERR_OK;
}

/*******************************************************************
*******************************************************************/

WERROR cli_svcctl_get_dispname(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return WERR_OK;
}

