/* 
   Unix SMB/CIFS implementation.
   DCERPC interface structures
   Copyright (C) Tim Potter 2003
   
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

struct dcerpc_hdr {
	uint8 rpc_vers;		/* RPC version */
	uint8 rpc_vers_minor;	/* Minor version */
	uint8 ptype;		/* Packet type */
	uint8 pfc_flags;	/* Fragmentation flags */
	uint8 drep[4];		/* NDR data representation */
	uint16 frag_len;	/* Total length of fragment */
	uint32 call_id;		/* Call identifier */
};

struct dcerpc_uuid {
	uint32 time_low;
	uint16 time_mid;
	uint16 time_hi_and_version;
	uint8 remaining[8];
};

struct syntax_id {
	struct dcerpc_uuid if_uuid;
	uint32 if_version;
};

struct p_ctx_list {
	uint16 cont_id;		/* Context id */
	uint8 num_ts;	        /* Number of transfer syntaxes */
	struct syntax_id *as;	/* Abstract syntax */
	struct syntax_id *ts;   /* Transfer syntaxes */
};

struct dcerpc_bind {
	struct {
		struct dcerpc_hdr hdr;    /* Header */
		uint16 max_xmit_frag;     /* Max transmit frag size */
		uint16 max_recv_frag;     /* Max receive frag size */
		uint32 assoc_group_id;    /* Association group */
		uint8 num_contexts;       /* Number of presentation contexts */
		struct p_ctx_list *ctx_list; /* Presentation context list */
		DATA_BLOB auth_verifier;
	} in;
	struct {
		struct dcerpc_hdr hdr;    /* Header */
		uint16 max_xmit_frag;     /* Max transmit frag size */
		uint16 max_recv_frag;     /* Max receive frag size */
		uint32 assoc_group_id;    /* Association group */
		DATA_BLOB auth_verifier;
	} out;
};

struct dcerpc_request {
	struct {
		struct dcerpc_hdr hdr;
		uint32 alloc_hint; /* Allocation hint */
		uint16 cont_id;    /* Context id */
		uint16 opnum;      /* Operation number */
		DATA_BLOB stub_data;
		DATA_BLOB auth_verifier;
	} in;
	struct {
		struct dcerpc_hdr hdr;
		uint32 alloc_hint;  /* Allocation hint */
		uint8 cancel_count; /* Context id */
		DATA_BLOB stub_data;
		DATA_BLOB auth_verifier;		
	} out;
};

struct cli_dcerpc_pipe {
	TALLOC_CTX *mem_ctx;
	uint16 fnum;
	int reference_count;
	uint32 call_id;
	struct cli_tree *tree;
};
