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

#ifndef _NT_DOMAIN_H		/* _NT_DOMAIN_H */
#define _NT_DOMAIN_H


/* dce/rpc support */
#include "rpc_dce.h"

/* dce/rpc authentication support */
#include "rpc_ntlmssp.h"
#include "rpc_netsec.h"

/* miscellaneous structures / defines */
#include "rpc_misc.h"

/* security descriptor structures */
#include "rpc_secdes.h"

/* different dce/rpc pipes */
#include "rpc_lsa.h"
#include "rpc_netlogon.h"
#include "rpc_samr.h"
#include "rpc_srvsvc.h"
#include "rpc_svcctl.h"
#include "rpc_wkssvc.h"
#include "rpc_atsvc.h"
#include "rpc_eventlog.h"
#include "rpc_dfs.h"

/* MS AD prototypes */
#include "sam.h"

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
		FUNCTION_MACRO, __LINE__)); \
		sleep(30); \
	} \
}

typedef struct parse_struct
{
	uint32 struct_start;

	char *data;		/* memory buffer */
	size_t data_size;	/* current memory buffer size */
	/* array memory offsets */
	uint32 start;
	uint32 end;

	uint32 offset;		/* offset currently being accessed in memory buffer */
	uint8 align;		/* data alignment */
	BOOL io;		/* parsing in or out of data stream */
	BOOL error;		/* error occurred while parsing (out of memory bounds) */
	BOOL bigendian;		/* big-endian data */

	struct parse_struct *next;

	uint32 struct_end;

}
prs_struct;

/*
 * Defines for io member of prs_struct.
 */

#define MARSHALL 0
#define UNMARSHALL 1

#define MARSHALLING(ps) (!(ps)->io)
#define UNMARSHALLING(ps) ((ps)->io)

#include "rpc_spoolss.h"

typedef struct netsec_auth_struct
{
	RPC_AUTH_NETSEC_NEG netsec_neg;
	uchar sess_key[16];

	uint32 seq_num;

}
netsec_auth_struct;

typedef struct ntlmssp_auth_struct
{
	RPC_AUTH_NTLMSSP_CHAL ntlmssp_chal;

	unsigned char ntlmssp_hash[258];
	uint32 ntlmssp_seq_num;

}
ntlmssp_auth_struct;

struct srv_auth_fns;

typedef struct rpcsrv_struct
{
	prs_struct data_i;	/* input data (intermediate, for fragments) */
	prs_struct rdata;	/* output data (to create fragments from */

	/* indicates how far in rdata we have got, creating fragments */
	uint32 rdata_offset;

	prs_struct smb_pdu;
	prs_struct rsmb_pdu;

	void *auth_info;
	struct srv_auth_fns *auth;

	/* set of authentication modules.  does not include noauth */
	uint32 num_auths;
	struct srv_auth_fns **auth_fns;

	BOOL auth_validated;
	BOOL faulted_once_before;

	RPC_HDR hdr;
	RPC_HDR_BA hdr_ba;
	RPC_HDR_RB hdr_rb;
	RPC_HDR_REQ hdr_req;

	vuser_key key;

	int c;			/* socket */

}
rpcsrv_struct;

struct cli_connection;

typedef struct cli_auth_fns
{
	/* these three will do for now.  they *should* match with server-side */
	BOOL (*create_bind_req) (struct cli_connection *, prs_struct *,
				 uint32, RPC_IFACE *, RPC_IFACE *);
	BOOL (*decode_bind_resp) (struct cli_connection *, prs_struct *);
	BOOL (*create_bind_cont) (struct cli_connection *, prs_struct *,
				  uint32);
	/* creates an authenticated PDU */
	BOOL (*cli_create_pdu) (struct cli_connection *, uint8,
				prs_struct *, int, int *,
				prs_struct *, uint8 *);
	/* decodes an authenticated PDU */
	BOOL (*cli_decode_pdu) (struct cli_connection *, prs_struct *,
				int, int);

}
cli_auth_fns;

typedef struct srv_auth_fns
{
	BOOL (*api_is_auth) (RPC_HDR_AUTH *, void **auth_info);

	/* state-based authentication: one to decode, one to generate */
	BOOL (*api_auth_chk) (rpcsrv_struct *, enum RPC_PKT_TYPE);
	BOOL (*api_auth_gen) (rpcsrv_struct *, prs_struct *,
			      enum RPC_PKT_TYPE);

	/* decodes an authenticated PDU */
	BOOL (*api_decode_pdu) (rpcsrv_struct *);
	/* creates an authenticated PDU */
	BOOL (*api_create_pdu) (rpcsrv_struct *, uint32, prs_struct *);

}
srv_auth_fns;

typedef struct pipes_struct
{
	struct pipes_struct *next, *prev;
	int pnum;
	vuser_key key;
	uint16 device_state;
	uint16 priority;
	fstring name;
	fstring pipe_srv_name;

	/* remote, server-side rpc redirection */
	struct msrpc_local *m;

	/* local, server-side rpc state processing */
	rpcsrv_struct *l;

}
pipes_struct;

typedef struct msrpc_service_fns
{
	void (*auth_init) (rpcsrv_struct *);
	void (*service_init) (char *);
	BOOL (*reload_services) (BOOL);
	int (*main_init) (int, char *[]);
	void (*idle) (void);

}
msrpc_service_fns;

struct api_struct
{
	char *name;
	uint8 opnum;
	BOOL (*fn) (rpcsrv_struct *, prs_struct *, prs_struct *);
};

struct acct_info
{
	fstring acct_name;	/* account name */
	fstring acct_desc;	/* account description */
	uint32 rid;		/* domain-relative RID */
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
	          uint32*const)

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
	void (*fn)(const char*, const DOM_SID*, uint32, \
	           SAM_USERINFO_CTR *const)
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
