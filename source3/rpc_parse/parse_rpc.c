
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"

extern int DEBUGLEVEL;


/*******************************************************************
interface/version dce/rpc pipe identification
********************************************************************/

#define TRANS_SYNT_V2             \
{                                 \
	{                             \
		0x04, 0x5d, 0x88, 0x8a,   \
		0xeb, 0x1c, 0xc9, 0x11,   \
		0x9f, 0xe8, 0x08, 0x00,   \
		0x2b, 0x10, 0x48, 0x60    \
	}, 0x02                       \
}                                 \

#define SYNT_NETLOGON_V2          \
{                                 \
	{                             \
		0x04, 0x5d, 0x88, 0x8a,   \
		0xeb, 0x1c, 0xc9, 0x11,   \
		0x9f, 0xe8, 0x08, 0x00,   \
		0x2b, 0x10, 0x48, 0x60    \
	}, 0x02                       \
}                                 \

#define SYNT_WKSSVC_V1            \
{                                 \
	{                             \
		0x98, 0xd0, 0xff, 0x6b,   \
		0x12, 0xa1, 0x10, 0x36,   \
		0x98, 0x33, 0x46, 0xc3,   \
		0xf8, 0x7e, 0x34, 0x5a    \
	}, 0x01                       \
}                                 \

#define SYNT_SRVSVC_V3            \
{                                 \
	{                             \
		0xc8, 0x4f, 0x32, 0x4b,   \
		0x70, 0x16, 0xd3, 0x01,   \
		0x12, 0x78, 0x5a, 0x47,   \
		0xbf, 0x6e, 0xe1, 0x88    \
	}, 0x03                       \
}                                 \

#define SYNT_LSARPC_V0            \
{                                 \
	{                             \
		0x78, 0x57, 0x34, 0x12,   \
		0x34, 0x12, 0xcd, 0xab,   \
		0xef, 0x00, 0x01, 0x23,   \
		0x45, 0x67, 0x89, 0xab    \
	}, 0x00                       \
}                                 \

#define SYNT_SAMR_V1              \
{                                 \
	{                             \
		0x78, 0x57, 0x34, 0x12,   \
		0x34, 0x12, 0xcd, 0xab,   \
		0xef, 0x00, 0x01, 0x23,   \
		0x45, 0x67, 0x89, 0xac    \
	}, 0x01                       \
}                                 \

#define SYNT_NETLOGON_V1          \
{                                 \
	{                             \
		0x78, 0x56, 0x34, 0x12,   \
		0x34, 0x12, 0xcd, 0xab,   \
		0xef, 0x00, 0x01, 0x23,   \
		0x45, 0x67, 0xcf, 0xfb    \
	}, 0x01                       \
}                                 \

#define SYNT_WINREG_V1            \
{                                 \
	{                             \
		0x01, 0xd0, 0x8c, 0x33,   \
		0x44, 0x22, 0xf1, 0x31,   \
		0xaa, 0xaa, 0x90, 0x00,   \
		0x38, 0x00, 0x10, 0x03    \
	}, 0x01                       \
}                                 \

#define SYNT_NONE_V0              \
{                                 \
	{                             \
		0x00, 0x00, 0x00, 0x00,   \
		0x00, 0x00, 0x00, 0x00,   \
		0x00, 0x00, 0x00, 0x00,   \
		0x00, 0x00, 0x00, 0x00    \
	}, 0x00                       \
}                                 \

/* pipe string names */
#define PIPE_SRVSVC   "\\PIPE\\srvsvc"
#define PIPE_SAMR     "\\PIPE\\samr"
#define PIPE_WINREG   "\\PIPE\\winreg"
#define PIPE_WKSSVC   "\\PIPE\\wkssvc"
#define PIPE_NETLOGON "\\PIPE\\NETLOGON"
#define PIPE_NTLSA    "\\PIPE\\ntlsa"
#define PIPE_NTSVCS   "\\PIPE\\ntsvcs"
#define PIPE_LSASS    "\\PIPE\\lsass"
#define PIPE_LSARPC   "\\PIPE\\lsarpc"

struct pipe_id_info pipe_names [] =
{
	/* client pipe , abstract syntax , server pipe   , transfer syntax */
	{ PIPE_LSARPC  , SYNT_LSARPC_V0  , PIPE_LSASS    , TRANS_SYNT_V2 },
	{ PIPE_SAMR    , SYNT_SAMR_V1    , PIPE_LSASS    , TRANS_SYNT_V2 },
	{ PIPE_NETLOGON, SYNT_NETLOGON_V1, PIPE_LSASS    , TRANS_SYNT_V2 },
	{ PIPE_SRVSVC  , SYNT_SRVSVC_V3  , PIPE_NTSVCS   , TRANS_SYNT_V2 },
	{ PIPE_WKSSVC  , SYNT_WKSSVC_V1  , PIPE_NTSVCS   , TRANS_SYNT_V2 },
	{ PIPE_WINREG  , SYNT_WINREG_V1  , PIPE_WINREG   , TRANS_SYNT_V2 },
	{ NULL         , SYNT_NONE_V0    , NULL          , SYNT_NONE_V0  }
};

/*******************************************************************
creates an RPC_HDR structure.
********************************************************************/
void make_rpc_hdr(RPC_HDR *hdr, enum RPC_PKT_TYPE pkt_type, uint8 flags,
				uint32 call_id, int data_len, int auth_len)
{
	if (hdr == NULL) return;

	hdr->major        = 5;               /* RPC version 5 */
	hdr->minor        = 0;               /* minor version 0 */
	hdr->pkt_type     = pkt_type;        /* RPC packet type */
	hdr->flags        = flags;           /* dce/rpc flags */
	hdr->pack_type    = 0x10;            /* packed data representation */
	hdr->frag_len     = data_len;        /* fragment length, fill in later */
	hdr->auth_len     = auth_len;        /* authentication length */
	hdr->call_id      = call_id;         /* call identifier - match incoming RPC */
}

/*******************************************************************
reads or writes an RPC_HDR structure.
********************************************************************/
void smb_io_rpc_hdr(char *desc,  RPC_HDR *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr");
	depth++;

	prs_uint8 ("major     ", ps, depth, &(rpc->major));
	prs_uint8 ("minor     ", ps, depth, &(rpc->minor));
	prs_uint8 ("pkt_type  ", ps, depth, &(rpc->pkt_type));
	prs_uint8 ("flags     ", ps, depth, &(rpc->flags));
	prs_uint32("pack_type ", ps, depth, &(rpc->pack_type));
	prs_uint16("frag_len  ", ps, depth, &(rpc->frag_len));
	prs_uint16("auth_len  ", ps, depth, &(rpc->auth_len));
	prs_uint32("call_id   ", ps, depth, &(rpc->call_id));
}

/*******************************************************************
creates an RPC_IFACE structure.
********************************************************************/
void make_rpc_iface(RPC_IFACE *ifc, char data[16], uint32 version)
{
	if (ifc == NULL || data == NULL) return;

	memcpy(ifc->data, data, sizeof(ifc->data)); /* 16 bytes of number */
	ifc->version = version; /* the interface number */
}

/*******************************************************************
reads or writes an RPC_IFACE structure.
********************************************************************/
void smb_io_rpc_iface(char *desc,  RPC_IFACE *ifc, prs_struct *ps, int depth)
{
	if (ifc == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_iface");
	depth++;

	prs_align(ps);

	prs_uint8s (False, "data   ", ps, depth, ifc->data, sizeof(ifc->data));
	prs_uint32 (       "version", ps, depth, &(ifc->version));
}

/*******************************************************************
creates an RPC_ADDR_STR structure.
********************************************************************/
void make_rpc_addr_str(RPC_ADDR_STR *str, char *name)
{
	if (str == NULL || name == NULL) return;

	str->len = strlen(name) + 1;
	fstrcpy(str->str, name);
}

/*******************************************************************
reads or writes an RPC_ADDR_STR structure.
********************************************************************/
void smb_io_rpc_addr_str(char *desc,  RPC_ADDR_STR *str, prs_struct *ps, int depth)
{
	if (str == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_addr_str");
	depth++;
	prs_align(ps);

	prs_uint16 (      "len", ps, depth, &(str->len));
	prs_uint8s (True, "str", ps, depth, (uchar*)str->str, str->len);
}

/*******************************************************************
creates an RPC_HDR_BBA structure.
********************************************************************/
void make_rpc_hdr_bba(RPC_HDR_BBA *bba, uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid)
{
	if (bba == NULL) return;

	bba->max_tsize = max_tsize; /* maximum transmission fragment size (0x1630) */
	bba->max_rsize = max_rsize; /* max receive fragment size (0x1630) */   
	bba->assoc_gid = assoc_gid; /* associated group id (0x0) */ 
}

/*******************************************************************
reads or writes an RPC_HDR_BBA structure.
********************************************************************/
void smb_io_rpc_hdr_bba(char *desc,  RPC_HDR_BBA *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_bba");
	depth++;

	prs_uint16("max_tsize", ps, depth, &(rpc->max_tsize));
	prs_uint16("max_rsize", ps, depth, &(rpc->max_rsize));
	prs_uint32("assoc_gid", ps, depth, &(rpc->assoc_gid));
}

/*******************************************************************
creates an RPC_HDR_RB structure.
********************************************************************/
void make_rpc_hdr_rb(RPC_HDR_RB *rpc, 
				uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid,
				uint32 num_elements, uint16 context_id, uint8 num_syntaxes,
				RPC_IFACE *abstract, RPC_IFACE *transfer)
{
	if (rpc == NULL) return;

	make_rpc_hdr_bba(&(rpc->bba), max_tsize, max_rsize, assoc_gid);

	rpc->num_elements = num_elements ; /* the number of elements (0x1) */
	rpc->context_id   = context_id   ; /* presentation context identifier (0x0) */
	rpc->num_syntaxes = num_syntaxes ; /* the number of syntaxes (has always been 1?)(0x1) */

	/* num and vers. of interface client is using */
	memcpy(&(rpc->abstract), abstract, sizeof(rpc->abstract));

	/* num and vers. of interface to use for replies */
	memcpy(&(rpc->transfer), transfer, sizeof(rpc->transfer));
}

/*******************************************************************
reads or writes an RPC_HDR_RB structure.
********************************************************************/
void smb_io_rpc_hdr_rb(char *desc,  RPC_HDR_RB *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_rb");
	depth++;

	smb_io_rpc_hdr_bba("", &(rpc->bba), ps, depth);

	prs_uint32("num_elements", ps, depth, &(rpc->num_elements));
	prs_uint16("context_id  ", ps, depth, &(rpc->context_id  ));
	prs_uint8 ("num_syntaxes", ps, depth, &(rpc->num_syntaxes));

	smb_io_rpc_iface("", &(rpc->abstract), ps, depth);
	smb_io_rpc_iface("", &(rpc->transfer), ps, depth);
}

/*******************************************************************
creates an RPC_RESULTS structure.

lkclXXXX only one reason at the moment!

********************************************************************/
void make_rpc_results(RPC_RESULTS *res, 
				uint8 num_results, uint16 result, uint16 reason)
{
	if (res == NULL) return;

	res->num_results = num_results; /* the number of results (0x01) */
	res->result      = result     ;  /* result (0x00 = accept) */
	res->reason      = reason     ;  /* reason (0x00 = no reason specified) */
}

/*******************************************************************
reads or writes an RPC_RESULTS structure.

lkclXXXX only one reason at the moment!

********************************************************************/
void smb_io_rpc_results(char *desc,  RPC_RESULTS *res, prs_struct *ps, int depth)
{
	if (res == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_results");
	depth++;

	prs_align(ps);
	
	prs_uint8 ("num_results", ps, depth, &(res->num_results));

	prs_align(ps);
	
	prs_uint16("result     ", ps, depth, &(res->result     ));
	prs_uint16("reason     ", ps, depth, &(res->reason     ));
}

/*******************************************************************
creates an RPC_HDR_BA structure.

lkclXXXX only one reason at the moment!

********************************************************************/
void make_rpc_hdr_ba(RPC_HDR_BA *rpc, 
				uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid,
				char *pipe_addr,
				uint8 num_results, uint16 result, uint16 reason,
				RPC_IFACE *transfer)
{
	if (rpc == NULL || transfer == NULL || pipe_addr == NULL) return;

	make_rpc_hdr_bba (&(rpc->bba ), max_tsize, max_rsize, assoc_gid);
	make_rpc_addr_str(&(rpc->addr), pipe_addr);
	make_rpc_results (&(rpc->res ), num_results, result, reason);

	/* the transfer syntax from the request */
	memcpy(&(rpc->transfer), transfer, sizeof(rpc->transfer));
}

/*******************************************************************
reads or writes an RPC_HDR_BA structure.
********************************************************************/
void smb_io_rpc_hdr_ba(char *desc,  RPC_HDR_BA *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_ba");
	depth++;

	smb_io_rpc_hdr_bba ("", &(rpc->bba)     , ps, depth);
	smb_io_rpc_addr_str("", &(rpc->addr)    , ps, depth);
	smb_io_rpc_results ("", &(rpc->res)     , ps, depth);
	smb_io_rpc_iface   ("", &(rpc->transfer), ps, depth);
}

/*******************************************************************
creates an RPC_HDR_REQ structure.
********************************************************************/
void make_rpc_hdr_req(RPC_HDR_REQ *hdr, uint32 data_len, uint16 opnum)
{
	if (hdr == NULL) return;

	hdr->alloc_hint   = data_len - 0x18; /* allocation hint */
	hdr->context_id   = 0;               /* presentation context identifier */
	hdr->opnum        = opnum;           /* opnum */
}

/*******************************************************************
reads or writes an RPC_HDR_REQ structure.
********************************************************************/
void smb_io_rpc_hdr_req(char *desc,  RPC_HDR_REQ *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_req");
	depth++;

	prs_uint32("alloc_hint", ps, depth, &(rpc->alloc_hint));
	prs_uint16("context_id", ps, depth, &(rpc->context_id));
	prs_uint16("opnum     ", ps, depth, &(rpc->opnum));
}

/*******************************************************************
creates an RPC_HDR_RESP structure.
********************************************************************/
void make_rpc_hdr_resp(RPC_HDR_RESP *hdr, uint32 data_len)
{
	if (hdr == NULL) return;

	hdr->alloc_hint   = data_len - 0x18; /* allocation hint */
	hdr->context_id   = 0;               /* presentation context identifier */
	hdr->cancel_count = 0;               /* cancel count */
	hdr->reserved     = 0;               /* 0 - reserved */
}

/*******************************************************************
reads or writes an RPC_HDR_RESP structure.
********************************************************************/
void smb_io_rpc_hdr_resp(char *desc,  RPC_HDR_RESP *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_resp");
	depth++;

	prs_uint32("alloc_hint", ps, depth, &(rpc->alloc_hint));
	prs_uint16("context_id", ps, depth, &(rpc->context_id));
	prs_uint8 ("cancel_ct ", ps, depth, &(rpc->cancel_count));
	prs_uint8 ("reserved  ", ps, depth, &(rpc->reserved));
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_REQ structure.
********************************************************************/
void make_rpc_auth_ntlmssp_req(RPC_AUTH_NTLMSSP_REQ *req,
				fstring ntlmssp_str, uint32 ntlmssp_ver,
				uint32 unknown_0, fstring myname, fstring domain)
{
	int len_myname = strlen(myname);
	int len_domain = strlen(domain);

	if (req == NULL) return;

	fstrcpy(req->ntlmssp_str, ntlmssp_str); /* "NTLMSSP" */
	req->ntlmssp_ver = ntlmssp_ver; /* 0x0000 0001 */

	req->unknown_0 = unknown_0 ; /* 0x00b2b3 */
	make_str_hdr(&req->hdr_myname, len_myname, len_myname, 1); 
	make_str_hdr(&req->hdr_domain, len_domain, len_domain, 1); 

	fstrcpy(req->myname, myname);
	fstrcpy(req->domain, domain);
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_REQ structure.
********************************************************************/
void smb_io_rpc_auth_ntlmssp_req(char *desc, RPC_AUTH_NTLMSSP_REQ *req, prs_struct *ps, int depth)
{
	if (req == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_req");
	depth++;

	prs_string("ntlmssp_str", ps, depth, req->ntlmssp_str, 0); /* "NTLMSSP" */
	prs_uint32("ntlmssp_ver", ps, depth, &(req->ntlmssp_ver ));

	prs_uint32("unknown_0 ", ps, depth, &(req->unknown_0 ));
	smb_io_strhdr("hdr_myname", &(req->hdr_myname), ps, depth); 
	smb_io_strhdr("hdr_domain", &(req->hdr_domain), ps, depth); 

	prs_string("myname", ps, depth, req->myname, req->hdr_myname.str_str_len); 
	prs_string("domain", ps, depth, req->domain, req->hdr_domain.str_str_len); 
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_RESP structure.
********************************************************************/
void make_rpc_auth_ntlmssp_resp(RPC_AUTH_NTLMSSP_RESP *rsp,
				uint8 auth_type, uint8 auth_level, uint8 stub_type_len,
				fstring ntlmssp_str, uint32 ntlmssp_ver,
				uint32 unknown_1, uint32 unknown_2, uint32 unknown_3,
				uint8 data[16])
{
	if (rsp == NULL) return;

	rsp->auth_type = auth_type; /* nt lm ssp 0x0a */
	rsp->auth_level = auth_level; /* 0x06 */
	rsp->stub_type_len = stub_type_len; /* dunno. */
	rsp->padding = 0; /* padding */

	rsp->ptr_0 = 1; /* non-zero pointer to something */

	fstrcpy(rsp->ntlmssp_str, ntlmssp_str); /* "NTLMSSP" */
	rsp->ntlmssp_ver = ntlmssp_ver; /* 0x0000 0002 */

	rsp->unknown_1 = unknown_1; /* 0x0000 0000 */
	rsp->unknown_2 = unknown_2; /* 0x00b2b3 */
	rsp->unknown_3 = unknown_3; /* 0x0082b1 */

	memcpy(rsp->data, data, sizeof(rsp->data)); /* 0x10 bytes of something, 8 of which are zeros */
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_RESP structure.
********************************************************************/
void smb_io_rpc_auth_ntlmssp_resp(char *desc, RPC_AUTH_NTLMSSP_RESP *rsp, prs_struct *ps, int depth)
{
	if (rsp == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_resp");
	depth++;

	prs_uint8("auth_type", ps, depth, &(rsp->auth_type)); /* nt lm ssp 0x0a */
	prs_uint8("auth_level", ps, depth, &(rsp->auth_level));/* 0x06 */
	prs_uint8("stub_type_len", ps, depth, &(rsp->stub_type_len));
	prs_uint8("padding", ps, depth, &(rsp->padding));

	prs_uint32("ptr_0", ps, depth, &(rsp->ptr_0 )); /* non-zero pointer to something */

	prs_string("ntlmssp_str", ps, depth, rsp->ntlmssp_str, 0); /* "NTLMSSP" */
	prs_uint32("ntlmssp_ver", ps, depth, &(rsp->ntlmssp_ver )); /* 0x0000 0002 */

	prs_uint32("unknown_1", ps, depth, &(rsp->unknown_1)); /* 0x0000 0000 */
	prs_uint32("unknown_2", ps, depth, &(rsp->unknown_2)); /* 0x00b2b3 */
	prs_uint32("unknown_3", ps, depth, &(rsp->unknown_3)); /* 0x0082b1 */

	prs_uint8s (False, "data", ps, depth, rsp->data, sizeof(rsp->data));
}

#if 0

/* attached to the end of encrypted rpc requests and responses */
/* RPC_AUTH_NTLMSSP_CHK */
typedef struct rpc_auth_ntlmssp_chk_info
{
	uint32 ver; /* 0x1 */
	uint8 data[12];

} RPC_AUTH_NTLMSSP_CHK;

#endif /* 0 */

