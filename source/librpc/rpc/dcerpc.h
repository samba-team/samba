/* 
   Unix SMB/CIFS implementation.
   DCERPC interface structures

   Copyright (C) Tim Potter 2003
   Copyright (C) Andrew Tridgell 2003
   
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

/*
  see http://www.opengroup.org/onlinepubs/9629399/chap12.htm for details
  of these structures

  note that the structure definitions here don't include some of the
  fields that are wire-artifacts. Those are put on the wire by the
  marshalling/unmarshalling routines in decrpc.c
*/

struct dcerpc_pipe {
	TALLOC_CTX *mem_ctx;
	uint16 fnum;
	int reference_count;
	uint32 call_id;
	uint32 srv_max_xmit_frag;
	uint32 srv_max_recv_frag;
	struct cli_tree *tree;
	unsigned flags;
};

/* dcerpc packet types */
#define DCERPC_PKT_REQUEST   0
#define DCERPC_PKT_RESPONSE  2
#define DCERPC_PKT_BIND     11
#define DCERPC_PKT_BIND_ACK 12
#define DCERPC_PKT_BIND_NAK 13

/* hdr.pfc_flags */
#define DCERPC_PFC_FLAG_FIRST   0x01
#define DCERPC_PFC_FLAG_LAST    0x02
#define DCERPC_PFC_FLAG_NOCALL  0x20

/* dcerpc pipe flags */
#define DCERPC_DEBUG_PRINT_IN 1
#define DCERPC_DEBUG_PRINT_OUT 2
#define DCERPC_DEBUG_PRINT_BOTH (DCERPC_DEBUG_PRINT_IN | DCERPC_DEBUG_PRINT_OUT)

/*
  all dcerpc packets use this structure. 
*/
struct dcerpc_packet {
	/* all requests and responses contain a dcerpc header */
	struct dcerpc_hdr {
		uint8 rpc_vers;		/* RPC version */
		uint8 rpc_vers_minor;	/* Minor version */
		uint8 ptype;		/* Packet type */
		uint8 pfc_flags;	/* Fragmentation flags */
		uint8 drep[4];		/* NDR data representation */
		uint16 frag_length;	/* Total length of fragment */
		uint16 auth_length;	/* authenticator length */
		uint32 call_id;		/* Call identifier */
	} hdr;

	union {
		struct dcerpc_bind {
			uint16 max_xmit_frag;
			uint16 max_recv_frag;
			uint32 assoc_group_id;
			uint8 num_contexts;
			struct {
				uint16 context_id;
				uint8 num_transfer_syntaxes;
				struct dcerpc_syntax_id {
					const char *uuid_str;
					uint32 if_version;
				} abstract_syntax;
				const struct dcerpc_syntax_id *transfer_syntaxes;
			} *ctx_list;
			DATA_BLOB auth_verifier;
		} bind;

		struct dcerpc_request {
			uint32 alloc_hint;
			uint16 context_id;
			uint16 opnum;
			DATA_BLOB stub_data;
			DATA_BLOB auth_verifier;
		} request;
	} in;

	union {
		struct dcerpc_bind_ack {
			uint16 max_xmit_frag;
			uint16 max_recv_frag;
			uint32 assoc_group_id;
			const char *secondary_address;
			uint8 num_results;
			struct {
				uint16 result;
				uint16 reason;
				struct dcerpc_syntax_id syntax;
			} *ctx_list;
			DATA_BLOB auth_verifier;
		} bind_ack;

		struct dcerpc_bind_nak {
			uint16 reject_reason;
			uint32 num_versions;
			uint32 *versions;
		} bind_nak;

		struct dcerpc_response {
			uint32 alloc_hint;
			uint16 context_id;
			uint8 cancel_count;
			DATA_BLOB stub_data;
			DATA_BLOB auth_verifier;		
		} response;
	} out;
};

