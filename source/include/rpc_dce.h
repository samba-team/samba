/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Paul Ashton                  1997-2000
   
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

#ifndef _DCE_RPC_H /* _DCE_RPC_H */
#define _DCE_RPC_H 

/* DCE/RPC packet types */

enum RPC_PKT_TYPE
{
	RPC_REQUEST     = 0x00,
	RPC_RESPONSE    = 0x02,
	RPC_FAULT       = 0x03,
	RPC_BIND        = 0x0B,
	RPC_BINDACK     = 0x0C,
	RPC_BINDNACK    = 0x0D,
	RPC_ALTCONT     = 0x0E,
	RPC_ALTCONTRESP = 0x0F,
	RPC_BINDRESP    = 0x10 /* not the real name!  this is undocumented! */
};

/* DCE/RPC flags */
#define RPC_FLG_FIRST 0x01
#define RPC_FLG_LAST  0x02
#define RPC_FLG_NOCALL 0x20


/* RPC_IFACE */
typedef struct rpc_iface_info
{
  uint8 data[16];    /* 16 bytes of rpc interface identification */
  uint32 version;    /* the interface version number */

} RPC_IFACE;

struct pipe_id_info
{
	/* the names appear not to matter: the syntaxes _do_ matter */

	char *client_pipe;
	RPC_IFACE abstr_syntax; /* this one is the abstract syntax id */

	char *server_pipe;  /* this one is the secondary syntax name */
	RPC_IFACE trans_syntax; /* this one is the primary syntax id */
};

/* RPC_HDR - dce rpc header */
typedef struct rpc_hdr_info
{
  uint8  major; /* 5 - RPC major version */
  uint8  minor; /* 0 - RPC minor version */
  uint8  pkt_type; /* RPC_PKT_TYPE - RPC response packet */
  uint8  flags; /* DCE/RPC flags */
  uint8  pack_type[4]; /* 0x10 00 00 00 - packed data representation */
  uint16 frag_len; /* fragment length - data size (bytes) inc header and tail. */
  uint16 auth_len; /* 0 - authentication length  */
  uint32 call_id; /* call identifier.  matches 12th uint32 of incoming RPC data. */

} RPC_HDR;

/* RPC_HDR_REQ - request rpc header */
typedef struct rpc_hdr_req_info
{
  uint32 alloc_hint;   /* allocation hint - data size (bytes) minus header and tail. */
  uint16 context_id;   /* 0 - presentation context identifier */
  uint16  opnum;        /* opnum */

} RPC_HDR_REQ;

/* RPC_HDR_RESP - response rpc header */
typedef struct rpc_hdr_resp_info
{
  uint32 alloc_hint;   /* allocation hint - data size (bytes) minus header and tail. */
  uint16 context_id;   /* 0 - presentation context identifier */
  uint8  cancel_count; /* 0 - cancel count */
  uint8  reserved;     /* 0 - reserved. */

} RPC_HDR_RESP;

/* RPC_HDR_FAULT - fault rpc header */
typedef struct rpc_hdr_fault_info
{
	uint32 status;
	uint32 reserved; /* 0x0000 0000 */

} RPC_HDR_FAULT;

/* RPC_HDR_NACK - nack rpc header */
typedef struct rpc_hdr_nack_info
{
	uint16 rej_code;

} RPC_HDR_NACK;

/* this seems to be the same string name depending on the name of the pipe,
 * but is more likely to be linked to the interface name
 * "srvsvc", "\\PIPE\\ntsvcs"
 * "samr", "\\PIPE\\lsass"
 * "wkssvc", "\\PIPE\\wksvcs"
 * "NETLOGON", "\\PIPE\\NETLOGON"
 */
/* RPC_ADDR_STR */
typedef struct rpc_addr_info
{
  uint16 len;   /* length of the string including null terminator */
  fstring str; /* the string above in single byte, null terminated form */

} RPC_ADDR_STR;

/* RPC_HDR_BBA */
typedef struct rpc_hdr_bba_info
{
  uint16 max_tsize;       /* maximum transmission fragment size (0x1630) */
  uint16 max_rsize;       /* max receive fragment size (0x1630) */
  uint32 assoc_gid;       /* associated group id (0x0) */

} RPC_HDR_BBA;

/* RPC_HDR_AUTHA */
typedef struct rpc_hdr_autha_info
{
	uint16 max_tsize;       /* maximum transmission fragment size (0x1630) */
	uint16 max_rsize;       /* max receive fragment size (0x1630) */

	uint8 auth_type; /* 0x0a */
	uint8 auth_level; /* 0x06 */
	uint8 stub_type_len; /* don't know */
	uint8 padding; /* padding */

	uint32 unknown; /* 0x0014a0c0 */

} RPC_HDR_AUTHA;

/* RPC_HDR_AUTH */
typedef struct rpc_hdr_auth_info
{
	uint8 auth_type; /* 0x0a */
	uint8 auth_level; /* 0x06 */
	uint8 stub_type_len; /* don't know */
	uint8 padding; /* padding */

	uint32 unknown; /* pointer */

} RPC_HDR_AUTH;

/* RPC_AUTH_VERIFIER */
typedef struct rpc_auth_ntlmssp_info
{
	fstring signature; /* authentication type */
	uint32  msg_type; /* message type (1,2,3) */

} RPC_AUTH_VERIFIER;

/* RPC_BIND_REQ - req bind */
typedef struct rpc_bind_req_info
{
  RPC_HDR_BBA bba;

  uint32 num_elements;    /* the number of elements (0x1) */
  uint16 context_id;      /* presentation context identifier (0x0) */
  uint8 num_syntaxes;     /* the number of syntaxes (has always been 1?)(0x1) */

  RPC_IFACE abstract;     /* num and vers. of interface client is using */
  RPC_IFACE transfer;     /* num and vers. of interface to use for replies */
  
} RPC_HDR_RB;

/* RPC_RESULTS - can only cope with one reason, right now... */
typedef struct rpc_results_info
{
/* uint8[] # 4-byte alignment padding, against SMB header */

  uint8 num_results; /* the number of results (0x01) */

/* uint8[] # 4-byte alignment padding, against SMB header */

  uint16 result; /* result (0x00 = accept) */
  uint16 reason; /* reason (0x00 = no reason specified) */

} RPC_RESULTS;

/* RPC_HDR_BA */
typedef struct rpc_hdr_ba_info
{
  RPC_HDR_BBA bba;

  RPC_ADDR_STR addr    ;  /* the secondary address string, as described earlier */
  RPC_RESULTS  res     ; /* results and reasons */
  RPC_IFACE    transfer; /* the transfer syntax from the request */

} RPC_HDR_BA;

#endif /* _DCE_RPC_H */

