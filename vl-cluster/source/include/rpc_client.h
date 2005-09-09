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

#define CLI_DO_RPC( pcli, ctx, p_idx, opnum, q_in, r_out, \
                             q_ps, r_ps, q_io_fn, r_io_fn, default_error ) \
{\
	SMB_ASSERT(pcli->pipe_idx == p_idx); \
	if (!prs_init( &q_ps, RPC_MAX_PDU_FRAG_LEN, ctx, MARSHALL )) { \
		return NT_STATUS_NO_MEMORY;\
	}\
	if (!prs_init( &r_ps, 0, ctx, UNMARSHALL )) {\
		prs_mem_free( &q_ps );\
		return NT_STATUS_NO_MEMORY;\
	}\
	if ( q_io_fn("", &q_in, &q_ps, 0) ) {\
		NTSTATUS _smb_pipe_stat_ = rpc_api_pipe_req(pcli, opnum, &q_ps, &r_ps); \
		if (!NT_STATUS_IS_OK(_smb_pipe_stat_)) {\
			prs_mem_free( &q_ps );\
			prs_mem_free( &r_ps );\
			return _smb_pipe_stat_;\
		}\
		if (!r_io_fn("", &r_out, &r_ps, 0)) {\
			prs_mem_free( &q_ps );\
			prs_mem_free( &r_ps );\
			return default_error;\
		}\
	} else {\
		prs_mem_free( &q_ps );\
		prs_mem_free( &r_ps );\
		return default_error;\
	}\
	prs_mem_free( &q_ps );\
	prs_mem_free( &r_ps );\
}

/* Arrrgg. Same but with WERRORS. Needed for registry code. */

#define CLI_DO_RPC_WERR( pcli, ctx, p_idx, opnum, q_in, r_out, \
                             q_ps, r_ps, q_io_fn, r_io_fn, default_error ) \
{\
	SMB_ASSERT(pcli->pipe_idx == p_idx); \
	if (!prs_init( &q_ps, RPC_MAX_PDU_FRAG_LEN, ctx, MARSHALL )) { \
		return WERR_NOMEM;\
	}\
	if (!prs_init( &r_ps, 0, ctx, UNMARSHALL )) {\
		prs_mem_free( &q_ps );\
		return WERR_NOMEM;\
	}\
	if ( q_io_fn("", &q_in, &q_ps, 0) ) {\
		NTSTATUS _smb_pipe_stat_ = rpc_api_pipe_req(pcli, opnum, &q_ps, &r_ps); \
		if (!NT_STATUS_IS_OK(_smb_pipe_stat_)) {\
			prs_mem_free( &q_ps );\
			prs_mem_free( &r_ps );\
			return ntstatus_to_werror(_smb_pipe_stat_);\
		}\
		if (!r_io_fn("", &r_out, &r_ps, 0)) {\
			prs_mem_free( &q_ps );\
			prs_mem_free( &r_ps );\
			return default_error;\
		}\
	} else {\
		prs_mem_free( &q_ps );\
		prs_mem_free( &r_ps );\
		return default_error;\
	}\
	prs_mem_free( &q_ps );\
	prs_mem_free( &r_ps );\
}

#endif /* _RPC_CLIENT_H */
