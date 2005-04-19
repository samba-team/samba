/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Gerald (Jerry) Carter         2005.
   
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

#ifndef _RPC_CLIENT_H
#define _RPC_CLIENT_H

/* macro to expand cookie-cutter code in cli_xxx() using rpc_api_pipe_req() */
		   
#define CLI_DO_RPC( pcli, ctx, pipe_num, opnum, q_in, r_out, \
                             q_ps, r_ps, q_io_fn, r_io_fn, default_error ) \
{	r_out.status = default_error;\
	prs_init( &q_ps, MAX_PDU_FRAG_LEN, ctx, MARSHALL ); \
	prs_init( &r_ps, 0, ctx, UNMARSHALL );\
	if ( q_io_fn("", &q_in, &q_ps, 0) ) {\
		if ( rpc_api_pipe_req(pcli, pipe_num, opnum, &q_ps, &r_ps) ) {\
			if (!r_io_fn("", &r_out, &r_ps, 0)) {\
				r_out.status = default_error;\
			}\
		}\
	}\
	prs_mem_free( &q_ps );\
	prs_mem_free( &r_ps );\
}

/* macro to expand cookie-cutter code in cli_xxx() using rpc_api_pipe_req_int() */

#define CLI_DO_RPC_EX( pcli, ctx, pipe_num, opnum, q_in, r_out, \
                             q_ps, r_ps, q_io_fn, r_io_fn, default_error ) \
{	r_out.status = default_error;\
	prs_init( &q_ps, MAX_PDU_FRAG_LEN, ctx, MARSHALL ); \
	prs_init( &r_ps, 0, ctx, UNMARSHALL );\
	if ( q_io_fn("", &q_in, &q_ps, 0) ) {\
		if ( rpc_api_pipe_req_int(pcli, opnum, &q_ps, &r_ps) ) {\
			if (!r_io_fn("", &r_out, &r_ps, 0)) {\
				r_out.status = default_error;\
			}\
		}\
	}\
	prs_mem_free( &q_ps );\
	prs_mem_free( &r_ps );\
}

#endif /* _RPC_CLIENT_H */
