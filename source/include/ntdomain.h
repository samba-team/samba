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
#include "rpc_svcctl.h"
#include "rpc_wkssvc.h"
#include "rpc_brs.h"
#include "rpc_atsvc.h"
#include "rpc_spoolss.h"
#include "rpc_eventlog.h"

/* 
 * A bunch of stuff that was put into smb.h
 * in the NTDOM branch - it didn't belong there.
 */
 
#define CHECK_STRUCT(data) \
{ \
	if ((data)->struct_start != 0xfefefefe || \
	    (data)->struct_end != 0xdcdcdcdc) \
	{ \
		DEBUG(0,("uninitialised structure (%s, %d)\n", \
		__FUNCTION__, __LINE__)); \
		sleep(30); \
	} \
}

typedef struct parse_struct
{
	uint32 struct_start;

	char *data; /* memory buffer */
	size_t data_size; /* current memory buffer size */
	/* array memory offsets */
	uint32 start; 
	uint32 end;

	uint32 offset; /* offset currently being accessed in memory buffer */
	uint8 align; /* data alignment */
	BOOL io; /* parsing in or out of data stream */
	BOOL error; /* error occurred while parsing (out of memory bounds) */

	struct parse_struct *next;

	uint32 struct_end;

} prs_struct;

typedef struct rpcsrv_struct
{
	prs_struct data_i; /* input data (intermediate, for fragments) */
	prs_struct rhdr; /* output header */
	prs_struct rfault; /* fault */
	prs_struct rdata; /* output data */
	prs_struct rdata_i; /* output data (intermediate, for fragments) */
	prs_struct rauth; /* output authentication verifier */
	prs_struct rverf; /* output verifier */
	prs_struct rntlm; /* output ntlmssp */

	uint32 rdata_offset;

	RPC_HDR       hdr;
	RPC_HDR_BA    hdr_ba;
	RPC_HDR_RB    hdr_rb;
	RPC_HDR_REQ   hdr_req;
	RPC_HDR_RESP  hdr_resp;
	RPC_HDR_FAULT hdr_fault;
	RPC_HDR_AUTH  auth_info;
	RPC_HDR_AUTHA autha_info;

	RPC_AUTH_NTLMSSP_VERIFIER auth_verifier;
	RPC_AUTH_NTLMSSP_NEG      ntlmssp_neg;
	RPC_AUTH_NTLMSSP_CHAL     ntlmssp_chal;
	RPC_AUTH_NTLMSSP_RESP     ntlmssp_resp;
	RPC_AUTH_NTLMSSP_CHK      ntlmssp_chk;

	BOOL ntlmssp_auth;
	BOOL ntlmssp_validated;
	unsigned char ntlmssp_hash[258];
	uint32 ntlmssp_seq_num;
	fstring user_name;
	fstring domain;
	fstring wks;

	uchar user_sess_key[16];

	/* per-user authentication info.  hmm, this not appropriate, but
	   it will do for now.  dcinfo contains NETLOGON-specific info,
	   so have to think of a better method.
	 */
	struct dcinfo dc;

} rpcsrv_struct;

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

	/* remote, server-side rpc redirection */
	struct msrpc_state *m;

	/* local, server-side rpc state processing */
	rpcsrv_struct *l;

	/* to store pdus being constructed / communicated from smb to msrpc */
	prs_struct smb_pdu;
	prs_struct rsmb_pdu;

	/* state-based info used in processing smbs to/from msrpc pdus */ 
	uint32 file_offset;
	uint32 prev_pdu_file_offset;
	uint32 hdr_offsets;

} pipes_struct;

struct api_struct
{  
  char *name;
  uint8 opnum;
  void (*fn) (rpcsrv_struct*, prs_struct*, prs_struct*);
};

struct acct_info
{
    fstring acct_name; /* account name */
    fstring acct_desc; /* account description */
    uint32  rid; /* domain-relative RID */
};

/*
 * higher order functions for use with msrpc client code
 */

#define ALIAS_FN(fn)\
	void (*fn)(const char*, const DOM_SID*, uint32, const char*)
#define ALIAS_INFO_FN(fn)\
	void (*fn)(const char*, const DOM_SID*, uint32, ALIAS_INFO_CTR *const)
#define ALIAS_MEM_FN(fn)\
	void(*fn)(const char*, const DOM_SID*, uint32, const char*,\
	          uint32, DOM_SID *const *const, char *const *const,\
	          uint8*const)

#define GROUP_FN(fn)\
	void (*fn)(const char*, const DOM_SID*, uint32, const char*)
#define GROUP_INFO_FN(fn)\
	void (*fn)(const char*, const DOM_SID*, uint32, GROUP_INFO_CTR *const)
#define GROUP_MEM_FN(fn)\
	void(*fn)(const char*, const DOM_SID*, uint32, const char*,\
	          uint32, const uint32*, char *const *const,\
	          uint32*const)

#define DOMAIN_FN(fn)\
	void (*fn)(const char*)
#define DOMAIN_INFO_FN(fn)\
	void (*fn)(const char*, const DOM_SID *, uint32, SAM_UNK_CTR *)

#define USER_FN(fn)\
	void (*fn)(const char*, const DOM_SID*, uint32, const char*)
#define USER_INFO_FN(fn)\
	void (*fn)(const char*, const DOM_SID*, uint32,\
	           SAM_USER_INFO_21 *const)
#define USER_MEM_FN(fn)\
	void (*fn)(const char*, const DOM_SID*, uint32, const char*,\
	           uint32, const uint32*, char *const *const, uint32* const)

#define DISP_FN(fn)\
	void (*fn)(const char*, const DOM_SID*, uint16, uint32, \
	           SAM_DISPINFO_CTR *)

#define REG_FN(fn)\
	void (*fn)(int, const char *, int)
#define REG_KEY_FN(fn)\
	void (*fn)(const char*, const char*, time_t)
#define REG_VAL_FN(fn)\
	void (*fn)(const char *, const char*, uint32, const BUFFER2 *)

#define SVC_QUERY_FN(fn)\
	void (*fn)(const QUERY_SERVICE_CONFIG *)
#define SVC_INFO_FN(fn)\
	void (*fn)(const ENUM_SRVC_STATUS *)

#define TPRT_INFO_FN(fn)\
	void (*fn)(const SRV_TPRT_INFO_CTR *)

#define PRINT_INFO_FN(fn)\
	void (*fn)(const char*, uint32, uint32, void  *const *const)
#define JOB_INFO_FN(fn)\
	void (*fn)(const char*, const char*, uint32, uint32, void *const *const)

#endif /* _NT_DOMAIN_H */

