/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   
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

#include "rpc_misc.h" /* this only pulls in STRHDR */


/* DCE/RPC packet types */

enum RPC_PKT_TYPE
{
	RPC_REQUEST = 0x00,
	RPC_RESPONSE = 0x02,
	RPC_BIND     = 0x0B,
	RPC_BINDACK  = 0x0C
};

/* DCE/RPC flags */
#define RPC_FLG_FIRST 0x01
#define RPC_FLG_LAST  0x02


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
  uint32 pack_type; /* 0x1000 0000 - packed data representation */
  uint16 frag_len; /* fragment length - data size (bytes) inc header and tail. */
  uint16 auth_len; /* 0 - authentication length  */
  uint32 call_id; /* call identifier.  matches 12th uint32 of incoming RPC data. */

} RPC_HDR;

/* RPC_HDR_REQ - ms request rpc header */
typedef struct rpc_hdr_req_info
{
  uint32 alloc_hint;   /* allocation hint - data size (bytes) minus header and tail. */
  uint16 context_id;   /* 0 - presentation context identifier */
  uint16  opnum;        /* opnum */

} RPC_HDR_REQ;

/* RPC_HDR_RESP - ms response rpc header */
typedef struct rpc_hdr_resp_info
{
  uint32 alloc_hint;   /* allocation hint - data size (bytes) minus header and tail. */
  uint16 context_id;   /* 0 - presentation context identifier */
  uint8  cancel_count; /* 0 - cancel count */
  uint8  reserved;     /* 0 - reserved. */

} RPC_HDR_RESP;

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

/* RPC_BIND_REQ - ms req bind */
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

/* this is TEMPORARY */
/* RPC_AUTH_VERIFIER */
typedef struct rpc_auth_verif_info
{
	fstring ssp_str;
	uint32 ssp_ver;

} RPC_AUTH_VERIFIER;

/* this is TEMPORARILY coded up as a specific structure */
/* this structure comes after the bind request */
/* RPC_AUTH_NTLMSSP_REQ */
typedef struct rpc_auth_ntlmssp_req_info
{
	fstring ntlmssp_str; /* "NTLMSSP" */
	uint32  ntlmssp_ver; /* 0x0000 0001 */

	uint32 unknown_0; /* 0x00b2b3 */
	STRHDR hdr_myname; /* offset is against START of this structure */
	STRHDR hdr_domain; /* offset is against START of this structure */

	fstring myname; /* calling workstation's name */
	fstring domain; /* calling workstations's domain */

} RPC_AUTH_NTLMSSP_REQ;

/* this is TEMPORARILY coded up as a specific structure */
/* this structure comes after the bind acknowledgement */
/* RPC_AUTH_NTLMSSP_RESP */
typedef struct rpc_auth_ntlmssp_resp_info
{
	uint8 auth_type; /* 0x0a */
	uint8 auth_level; /* 0x06 */
	uint8 stub_type_len; /* don't know */
	uint8 padding; /* padding */

	uint32 ptr_0; /* non-zero pointer to something */

	fstring ntlmssp_str; /* "NTLMSSP" */
	uint32  ntlmssp_ver; /* 0x0000 0002 */

	uint32 unknown_1; /* 0x0000 0000 */
	uint32 unknown_2; /* 0x00b2b3 */
	uint32 unknown_3; /* 0x0082b1 */

	uint8 data[16]; /* 0x10 bytes of something */

} RPC_AUTH_NTLMSSP_RESP;

/* attached to the end of encrypted rpc requests and responses */
/* RPC_AUTH_NTLMSSP_CHK */
typedef struct rpc_auth_ntlmssp_chk_info
{
	uint32 ver; /* 0x1 */
	uint8 data[12];

} RPC_AUTH_NTLMSSP_CHK;

#endif /* _DCE_RPC_H */

