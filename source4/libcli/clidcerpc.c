/* 
   Unix SMB/CIFS implementation.
   raw dcerpc operations

   Copyright (C) Tim Potter, 2003
   
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

struct cli_dcerpc_pipe *cli_dcerpc_pipe_init(struct cli_tree *tree)
{
	struct cli_dcerpc_pipe *p;

	TALLOC_CTX *mem_ctx = talloc_init("cli_dcerpc_tree");
	if (mem_ctx == NULL)
		return NULL;

	p = talloc_zero(mem_ctx, sizeof(*p));
	if (!p) {
		talloc_destroy(mem_ctx);
		return NULL;
	}

	p->mem_ctx = mem_ctx;
	p->tree = tree;
	p->tree->reference_count++;

	return p;
}

void cli_dcerpc_pipe_close(struct cli_dcerpc_pipe *p)
{
	if (!p) return;
	p->reference_count--;
	if (p->reference_count <= 0) {
		cli_tree_close(p->tree);
		talloc_destroy(p->mem_ctx);
	}
}

static void init_dcerpc_hdr(struct dcerpc_hdr *hdr, uint8 ptype,
			    uint8 pfc_flags, uint32 call_id)
{
        hdr->rpc_vers = 5;
        hdr->rpc_vers_minor = 0;
        hdr->ptype = ptype;
        hdr->pfc_flags = pfc_flags;
        hdr->drep[0] = 0x10; /* Little endian */
        hdr->call_id = call_id;
}

struct syntax_id trans_synt_v2 = 
{
	{
		0x8a885d04, 0x1ceb, 0x11c9,
		{ 0x9f, 0xe8, 0x08, 0x00,
		0x2b, 0x10, 0x48, 0x60 }
	}, 0x02
};

struct syntax_id synt_netlogon_v2 =
{
	{
		0x8a885d04, 0x1ceb, 0x11c9,
		{ 0x9f, 0xe8, 0x08, 0x00,
		0x2b, 0x10, 0x48, 0x60 }
	}, 0x02
};

struct syntax_id synt_wkssvc_v1 =
{
	{
		0x6bffd098, 0xa112, 0x3610,
		{ 0x98, 0x33, 0x46, 0xc3,
		0xf8, 0x7e, 0x34, 0x5a }
	}, 0x01
};

struct syntax_id synt_srvsvc_v3 =
{
	{
		0x4b324fc8, 0x1670, 0x01d3,
		{ 0x12, 0x78, 0x5a, 0x47,
		0xbf, 0x6e, 0xe1, 0x88 }
	}, 0x03
};

struct syntax_id synt_lsarpc_v0 =
{
	{
		0x12345778, 0x1234, 0xabcd,
		{ 0xef, 0x00, 0x01, 0x23,
		0x45, 0x67, 0x89, 0xab }
	}, 0x00
};

struct syntax_id synt_lsarpc_v0_ds =
{
	{
		0x3919286a, 0xb10c, 0x11d0,
		{ 0x9b, 0xa8, 0x00, 0xc0,
		0x4f, 0xd9, 0x2e, 0xf5 }
	}, 0x00
};

struct syntax_id synt_samr_v1 =
{
	{
		0x12345778, 0x1234, 0xabcd,
		{ 0xef, 0x00, 0x01, 0x23,
		0x45, 0x67, 0x89, 0xac }
	}, 0x01
};

struct syntax_id synt_netlogon_v1 =
{
	{
		0x12345678, 0x1234, 0xabcd,
		{ 0xef, 0x00, 0x01, 0x23,
		0x45, 0x67, 0xcf, 0xfb }
	}, 0x01
};

struct syntax_id synt_winreg_v1 =
{
	{
		0x338cd001, 0x2244, 0x31f1,
		{ 0xaa, 0xaa, 0x90, 0x00,
		0x38, 0x00, 0x10, 0x03 }
	}, 0x01
};

struct syntax_id synt_spoolss_v1 =
{
	{
		0x12345678, 0x1234, 0xabcd,
		{ 0xef, 0x00, 0x01, 0x23,
		0x45, 0x67, 0x89, 0xab }
	}, 0x01
};

struct syntax_id synt_netdfs_v3 =
{
        {
                0x4fc742e0, 0x4a10, 0x11cf,
                { 0x82, 0x73, 0x00, 0xaa,
                  0x00, 0x4a, 0xe6, 0x73 }
        }, 0x03
};

struct known_pipes {
	const char *client_pipe;
	struct p_ctx_list ctx_list;
};

const struct known_pipes known_pipes[] =
{
	{ PIPE_LSARPC  , { 0, 1, &synt_lsarpc_v0,   &trans_synt_v2 }},
	{ PIPE_SAMR    , { 0, 1, &synt_samr_v1,     &trans_synt_v2 }},
	{ PIPE_NETLOGON, { 0, 1, &synt_netlogon_v1, &trans_synt_v2 }},
	{ PIPE_SRVSVC  , { 0, 1, &synt_srvsvc_v3 ,  &trans_synt_v2 }},
	{ PIPE_WKSSVC  , { 0, 1, &synt_wkssvc_v1 ,  &trans_synt_v2 }},
	{ PIPE_WINREG  , { 0, 1, &synt_winreg_v1 ,  &trans_synt_v2 }},
	{ PIPE_SPOOLSS , { 0, 1, &synt_spoolss_v1,  &trans_synt_v2 }},
	{ PIPE_NETDFS  , { 0, 1, &synt_netdfs_v3 ,  &trans_synt_v2 }},
	{ NULL         , { 0, 0, NULL,              NULL }}
};

/* Perform a bind using the given syntaxes */

NTSTATUS cli_dcerpc_bind(struct cli_dcerpc_pipe *p, int num_contexts,
			 struct p_ctx_list *ctx_list)
{
	TALLOC_CTX *mem_ctx;
        struct dcerpc_bind parms;
	NTSTATUS status;

	mem_ctx = talloc_init("cli_dcerpc_bind");

        ZERO_STRUCT(parms);
 
	init_dcerpc_hdr(&parms.in.hdr, RPC_BIND, RPC_FLG_FIRST|RPC_FLG_LAST,
			p->call_id++);

        parms.in.max_xmit_frag = 5680;
        parms.in.max_recv_frag = 5680;
        parms.in.num_contexts = num_contexts;
	parms.in.ctx_list = ctx_list;
 
        status = dcerpc_raw_bind(p, &parms);

	talloc_destroy(mem_ctx);

	return status;	
}

/* Perform a bind using the given well-known pipe name */

NTSTATUS cli_dcerpc_bind_byname(struct cli_dcerpc_pipe *p, 
				const char *pipe_name)
{
	const struct known_pipes *pi;

	for (pi = known_pipes; pi->client_pipe; pi++) {
		if (strequal(&pi->client_pipe[5], pipe_name))
			break;
	}
	
	if (pi->client_pipe == NULL)
		return NT_STATUS_UNSUCCESSFUL;


	return cli_dcerpc_bind(p, 1, &pi->ctx_list);
}

NTSTATUS cli_dcerpc_request(struct cli_dcerpc_pipe *p, uint16 opnum,
			    DATA_BLOB stub_data)
{
	TALLOC_CTX *mem_ctx;
	struct dcerpc_request parms;
	NTSTATUS status;

	mem_ctx = talloc_init("cli_dcerpc_request");

	ZERO_STRUCT(parms);
	
	init_dcerpc_hdr(&parms.in.hdr, RPC_REQUEST, 
			RPC_FLG_FIRST|RPC_FLG_LAST, p->call_id++);

	parms.in.alloc_hint = 0;
	parms.in.cont_id = 0;
	parms.in.opnum = opnum;
	parms.in.stub_data = stub_data;

	status = dcerpc_raw_request(p, &parms);	

	talloc_destroy(mem_ctx);

	return status;
}
