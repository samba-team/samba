/* 
   Unix SMB/CIFS implementation.

   DCERPC client side interface structures

   Copyright (C) 2008 Jelmer Vernooij
   
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

/* This is a public header file that is installed as part of Samba. 
 * If you remove any functions or change their signature, update 
 * the so version number. */

#ifndef __DCERPC_H__
#define __DCERPC_H__

#include "includes.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/epmapper.h"

struct loadparm_context;
struct cli_credentials;

/**
 * Connection to a particular DCE/RPC interface.
 */
struct dcerpc_pipe {
	const struct ndr_interface_table *table;

	/** SMB context used when transport is ncacn_np. */
	struct cli_state *cli;

	/** Samba 3 DCE/RPC client context. */
	struct rpc_pipe_client *rpc_cli;
};

struct rpc_request {
	const struct ndr_interface_call *call;
	prs_struct q_ps;
	uint32_t opnum;
	struct dcerpc_pipe *pipe;
	void *r;
};

enum dcerpc_transport_t {
	NCA_UNKNOWN, NCACN_NP, NCACN_IP_TCP, NCACN_IP_UDP, NCACN_VNS_IPC, 
	NCACN_VNS_SPP, NCACN_AT_DSP, NCADG_AT_DDP, NCALRPC, NCACN_UNIX_STREAM, 
	NCADG_UNIX_DGRAM, NCACN_HTTP, NCADG_IPX, NCACN_SPX };


/** this describes a binding to a particular transport/pipe */
struct dcerpc_binding {
	enum dcerpc_transport_t transport;
	struct ndr_syntax_id object;
	const char *host;
	const char *target_hostname;
	const char *endpoint;
	const char **options;
	uint32_t flags;
	uint32_t assoc_group_id;
};

#endif /* __DCERPC_H__ */
