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

#ifndef _NT_DOMAIN_H /* _NT_DOMAIN_H */
#define _NT_DOMAIN_H 


/* dce/rpc support */
#include "rpc_dce.h"

/* miscellaneous structures / defines */
#include "rpc_misc.h"

/* security descriptor structures */
#include "rpc_secdes.h" 

/* different dce/rpc pipes */
#include "rpc_lsa.h"
#include "rpc_netlogon.h"
#include "rpc_reg.h"
#include "rpc_samr.h"
#include "rpc_srvsvc.h"
#include "rpc_wkssvc.h"

/* 
 * A bunch of stuff that was put into smb.h
 * in the NTDOM branch - it didn't belong there.
 */
 
typedef struct
{
	struct mem_buf *data; /* memory buffer */
	uint32 offset; /* offset currently being accessed in memory buffer */
	uint8 align; /* data alignment */
	BOOL io; /* parsing in or out of data stream */

} prs_struct;

typedef struct pipes_struct
{
	struct pipes_struct *next, *prev;
	int pnum;
	connection_struct *conn;
	uint16 vuid;
	BOOL open; /* open connection */
	uint16 device_state;
	uint16 priority;
	fstring name;
	fstring pipe_srv_name;

	prs_struct rhdr; /* output header */
	prs_struct rdata; /* output data */
	prs_struct rdata_i; /* output data (intermediate, for fragments) */
	prs_struct rauth; /* output authentication verifier */
	prs_struct rverf; /* output verifier */
	prs_struct rntlm; /* output ntlmssp */

	RPC_HDR     hdr;
	RPC_HDR_BA  hdr_ba;
	RPC_HDR_RB  hdr_rb;
	RPC_HDR_REQ  hdr_req;
	RPC_HDR_RESP hdr_resp;
	RPC_HDR_AUTH  auth_info;
	RPC_HDR_AUTHA autha_info;

	RPC_AUTH_VERIFIER     auth_verifier;
	RPC_AUTH_NTLMSSP_NEG  ntlmssp_neg;
	RPC_AUTH_NTLMSSP_CHAL ntlmssp_chal;
	RPC_AUTH_NTLMSSP_RESP ntlmssp_resp;
	RPC_AUTH_NTLMSSP_CHK  ntlmssp_chk;

	BOOL ntlmssp_auth;
	BOOL ntlmssp_validated;
	unsigned char ntlmssp_hash[258];
	uint32 ntlmssp_seq_num;
	fstring user_name;
	fstring domain;
	fstring wks;

	uint32 file_offset;
	uint32 hdr_offsets;
	uint32 frag_len_left;
	uint32 next_frag_start;

} pipes_struct;

struct api_struct
{  
  char *name;
  uint8 opnum;
  void (*fn) (uint16 vuid, prs_struct*, prs_struct*);
};

struct mem_desc
{  
	/* array memory offsets */
	uint32 start; 
	uint32 end;
};
   
struct mem_buf
{  
	BOOL dynamic; /* True iff data has been dynamically allocated
					 (and therefore can be freed) */
	char *data;
	uint32 data_size;
	uint32 data_used;

	uint32 margin; /* safety margin when reallocing. */
				   /* this can be abused quite nicely */
	uint8 align;   /* alignment of data structures (smb, dce/rpc, udp etc) */

	struct mem_desc offset;

	struct mem_buf *next;
};

typedef struct
{  
	uint32 rid;
	char *name;

} rid_name;

struct acct_info
{
    fstring acct_name; /* account name */
    uint32  user_rid; /* domain-relative RID */
};

#endif /* _NT_DOMAIN_H */

