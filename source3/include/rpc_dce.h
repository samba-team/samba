/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   
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

#ifndef _DCE_RPC_H /* _DCE_RPC_H */
#define _DCE_RPC_H 

#define RPC_AUTH_SCHANNEL_SIGN_OR_SEAL_CHK_LEN 	0x20

/* Maximum size of the signing data in a fragment. */
#define RPC_MAX_SIGN_SIZE 0x38 /* 56 */

/* Maximum PDU fragment size. */
/* #define MAX_PDU_FRAG_LEN 0x1630		this is what wnt sets */
#define RPC_MAX_PDU_FRAG_LEN 0x10b8			/* this is what w2k sets */

#define RPC_IFACE_LEN (UUID_SIZE + 4)

#define RPC_HEADER_LEN 16

#define RPC_HDR_REQ_LEN 8

/* RPC_HDR_RESP - ms response rpc header */
typedef struct rpc_hdr_resp_info {
	uint32 alloc_hint;   /* allocation hint - data size (bytes) minus header and tail. */
	uint16 context_id;   /* 0 - presentation context identifier */
	uint8  cancel_count; /* 0 - cancel count */
	uint8  reserved;     /* 0 - reserved. */
} RPC_HDR_RESP;

#define RPC_HDR_RESP_LEN 8

/* RPC_HDR_AUTH */
typedef struct rpc_hdr_auth_info {
	uint8 auth_type; /* See XXX_AUTH_TYPE above. */
	uint8 auth_level; /* See RPC_PIPE_AUTH_XXX_LEVEL above. */
	uint8 auth_pad_len;
	uint8 auth_reserved;
	uint32 auth_context_id;
} RPC_HDR_AUTH;

#define RPC_HDR_AUTH_LEN 8

#endif /* _DCE_RPC_H */
