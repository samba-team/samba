
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

#define SYNT_SVCCTL_V2          \
{                                 \
	{                             \
		0x81, 0xbb, 0x7a, 0x36,   \
		0x44, 0x98, 0xf1, 0x35,   \
		0xad, 0x32, 0x98, 0xf0,   \
		0x38, 0x00, 0x10, 0x03    \
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

struct pipe_id_info pipe_names [] =
{
	/* client pipe , abstract syntax , server pipe   , transfer syntax */
	{ PIPE_LSARPC  , SYNT_LSARPC_V0  , PIPE_LSASS    , TRANS_SYNT_V2 },
	{ PIPE_SAMR    , SYNT_SAMR_V1    , PIPE_LSASS    , TRANS_SYNT_V2 },
	{ PIPE_NETLOGON, SYNT_NETLOGON_V1, PIPE_LSASS    , TRANS_SYNT_V2 },
	{ PIPE_SRVSVC  , SYNT_SRVSVC_V3  , PIPE_NTSVCS   , TRANS_SYNT_V2 },
	{ PIPE_SVCCTL  , SYNT_SVCCTL_V2  , PIPE_NTSVCS   , TRANS_SYNT_V2 },
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
reads or writes an RPC_IFACE structure.
********************************************************************/
static void smb_io_rpc_iface(char *desc,  RPC_IFACE *ifc, prs_struct *ps, int depth)
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
static void make_rpc_addr_str(RPC_ADDR_STR *str, char *name)
{
	if (str == NULL || name == NULL) return;

	str->len = strlen(name) + 1;
	fstrcpy(str->str, name);
}

/*******************************************************************
reads or writes an RPC_ADDR_STR structure.
********************************************************************/
static void smb_io_rpc_addr_str(char *desc,  RPC_ADDR_STR *str, prs_struct *ps, int depth)
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
static void make_rpc_hdr_bba(RPC_HDR_BBA *bba, uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid)
{
	if (bba == NULL) return;

	bba->max_tsize = max_tsize; /* maximum transmission fragment size (0x1630) */
	bba->max_rsize = max_rsize; /* max receive fragment size (0x1630) */   
	bba->assoc_gid = assoc_gid; /* associated group id (0x0) */ 
}

/*******************************************************************
reads or writes an RPC_HDR_BBA structure.
********************************************************************/
static void smb_io_rpc_hdr_bba(char *desc,  RPC_HDR_BBA *rpc, prs_struct *ps, int depth)
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
static void make_rpc_results(RPC_RESULTS *res, 
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
static void smb_io_rpc_results(char *desc,  RPC_RESULTS *res, prs_struct *ps, int depth)
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
void make_rpc_hdr_req(RPC_HDR_REQ *hdr, uint32 alloc_hint, uint16 opnum)
{
	if (hdr == NULL) return;

	hdr->alloc_hint   = alloc_hint; /* allocation hint */
	hdr->context_id   = 0;         /* presentation context identifier */
	hdr->opnum        = opnum;     /* opnum */
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
creates an RPC_HDR_AUTHA structure.
********************************************************************/
void make_rpc_hdr_autha(RPC_HDR_AUTHA *rai,
				uint16 max_tsize, uint16 max_rsize,
				uint8 auth_type, uint8 auth_level,
				uint8 stub_type_len)
{
	if (rai == NULL) return;

	rai->max_tsize = max_tsize; /* maximum transmission fragment size (0x1630) */
	rai->max_rsize = max_rsize; /* max receive fragment size (0x1630) */   

	rai->auth_type     = auth_type; /* nt lm ssp 0x0a */
	rai->auth_level    = auth_level; /* 0x06 */
	rai->stub_type_len = stub_type_len; /* 0x00 */
	rai->padding       = 0; /* padding 0x00 */

	rai->unknown       = 0x0014a0c0; /* non-zero pointer to something */
}

/*******************************************************************
reads or writes an RPC_HDR_AUTHA structure.
********************************************************************/
void smb_io_rpc_hdr_autha(char *desc, RPC_HDR_AUTHA *rai, prs_struct *ps, int depth)
{
	if (rai == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_autha");
	depth++;

	prs_uint16("max_tsize    ", ps, depth, &(rai->max_tsize));
	prs_uint16("max_rsize    ", ps, depth, &(rai->max_rsize));

	prs_uint8 ("auth_type    ", ps, depth, &(rai->auth_type    )); /* 0x0a nt lm ssp */
	prs_uint8 ("auth_level   ", ps, depth, &(rai->auth_level   ));/* 0x06 */
	prs_uint8 ("stub_type_len", ps, depth, &(rai->stub_type_len));
	prs_uint8 ("padding      ", ps, depth, &(rai->padding      ));

	prs_uint32("unknown      ", ps, depth, &(rai->unknown      )); /* 0x0014a0c0 */
}

/*******************************************************************
checks an RPC_HDR_AUTH structure.
********************************************************************/
BOOL rpc_hdr_auth_chk(RPC_HDR_AUTH *rai)
{
	return (rai->auth_type == 0x0a && rai->auth_level == 0x06);
}

/*******************************************************************
creates an RPC_HDR_AUTH structure.
********************************************************************/
void make_rpc_hdr_auth(RPC_HDR_AUTH *rai,
				uint8 auth_type, uint8 auth_level,
				uint8 stub_type_len,
				uint32 ptr)
{
	if (rai == NULL) return;

	rai->auth_type     = auth_type; /* nt lm ssp 0x0a */
	rai->auth_level    = auth_level; /* 0x06 */
	rai->stub_type_len = stub_type_len; /* 0x00 */
	rai->padding       = 0; /* padding 0x00 */

	rai->unknown       = ptr; /* non-zero pointer to something */
}

/*******************************************************************
reads or writes an RPC_HDR_AUTH structure.
********************************************************************/
void smb_io_rpc_hdr_auth(char *desc, RPC_HDR_AUTH *rai, prs_struct *ps, int depth)
{
	if (rai == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_auth");
	depth++;

	prs_uint8 ("auth_type    ", ps, depth, &(rai->auth_type    )); /* 0x0a nt lm ssp */
	prs_uint8 ("auth_level   ", ps, depth, &(rai->auth_level   ));/* 0x06 */
	prs_uint8 ("stub_type_len", ps, depth, &(rai->stub_type_len));
	prs_uint8 ("padding      ", ps, depth, &(rai->padding      ));

	prs_uint32("unknown      ", ps, depth, &(rai->unknown      )); /* 0x0014a0c0 */
}

/*******************************************************************
checks an RPC_AUTH_VERIFIER structure.
********************************************************************/
BOOL rpc_auth_verifier_chk(RPC_AUTH_VERIFIER *rav,
				char *signature, uint32 msg_type)
{
	return (strequal(rav->signature, signature) && rav->msg_type == msg_type);
}

/*******************************************************************
creates an RPC_AUTH_VERIFIER structure.
********************************************************************/
void make_rpc_auth_verifier(RPC_AUTH_VERIFIER *rav,
				char *signature, uint32 msg_type)
{
	if (rav == NULL) return;

	fstrcpy(rav->signature, signature); /* "NTLMSSP" */
	rav->msg_type = msg_type; /* NTLMSSP_MESSAGE_TYPE */
}

/*******************************************************************
reads or writes an RPC_AUTH_VERIFIER structure.
********************************************************************/
void smb_io_rpc_auth_verifier(char *desc, RPC_AUTH_VERIFIER *rav, prs_struct *ps, int depth)
{
	if (rav == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_verifier");
	depth++;

	prs_string("signature", ps, depth, rav->signature, 0, sizeof(rav->signature)); /* "NTLMSSP" */
	prs_uint32("msg_type ", ps, depth, &(rav->msg_type  )); /* NTLMSSP_MESSAGE_TYPE */
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_NEG structure.
********************************************************************/
void make_rpc_auth_ntlmssp_neg(RPC_AUTH_NTLMSSP_NEG *neg,
				uint32 neg_flgs,
				fstring myname, fstring domain)
{
	int len_myname = strlen(myname);
	int len_domain = strlen(domain);

	if (neg == NULL) return;

	neg->neg_flgs = neg_flgs ; /* 0x00b2b3 */

	make_str_hdr(&neg->hdr_domain, len_domain, len_domain, 0x20 + len_myname); 
	make_str_hdr(&neg->hdr_myname, len_myname, len_myname, 0x20); 

	fstrcpy(neg->myname, myname);
	fstrcpy(neg->domain, domain);
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_NEG structure.

*** lkclXXXX HACK ALERT! ***

********************************************************************/
void smb_io_rpc_auth_ntlmssp_neg(char *desc, RPC_AUTH_NTLMSSP_NEG *neg, prs_struct *ps, int depth)
{
	if (neg == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_neg");
	depth++;

	prs_uint32("neg_flgs ", ps, depth, &(neg->neg_flgs));

	if (ps->io)
	{
		uint32 old_offset;

		/* reading */

		ZERO_STRUCTP(neg);

		smb_io_strhdr("hdr_domain", &(neg->hdr_domain), ps, depth); 
		smb_io_strhdr("hdr_myname", &(neg->hdr_myname), ps, depth); 

		old_offset = ps->offset;

		ps->offset = neg->hdr_myname  .buffer + 0x50; /* lkclXXXX HACK! */
		prs_uint8s(True , "myname", ps, depth, (uint8*)neg->myname  , MIN(neg->hdr_myname  .str_str_len, sizeof(neg->myname  ))); 
		old_offset += neg->hdr_myname  .str_str_len;

		ps->offset = neg->hdr_domain  .buffer + 0x50; /* lkclXXXX HACK! */
		prs_uint8s(True , "domain", ps, depth, (uint8*)neg->domain  , MIN(neg->hdr_domain  .str_str_len, sizeof(neg->domain  ))); 
		old_offset += neg->hdr_domain  .str_str_len;

		ps->offset = old_offset;
	}
	else
	{
		/* writing */
		smb_io_strhdr("hdr_domain", &(neg->hdr_domain), ps, depth); 
		smb_io_strhdr("hdr_myname", &(neg->hdr_myname), ps, depth); 

		prs_uint8s(True , "myname", ps, depth, (uint8*)neg->myname  , MIN(neg->hdr_myname  .str_str_len, sizeof(neg->myname  ))); 
		prs_uint8s(True , "domain", ps, depth, (uint8*)neg->domain  , MIN(neg->hdr_domain  .str_str_len, sizeof(neg->domain  ))); 
	}
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_CHAL structure.
********************************************************************/
void make_rpc_auth_ntlmssp_chal(RPC_AUTH_NTLMSSP_CHAL *chl,
				uint32 neg_flags,
				uint8 challenge[8])
{
	if (chl == NULL) return;

	chl->unknown_1 = 0x0; 
	chl->unknown_2 = 0x00000028;
	chl->neg_flags = neg_flags; /* 0x0082b1 */

	memcpy(chl->challenge, challenge, sizeof(chl->challenge)); 
	bzero (chl->reserved ,            sizeof(chl->reserved)); 
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_CHAL structure.
********************************************************************/
void smb_io_rpc_auth_ntlmssp_chal(char *desc, RPC_AUTH_NTLMSSP_CHAL *chl, prs_struct *ps, int depth)
{
	if (chl == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_chal");
	depth++;

	prs_uint32("unknown_1", ps, depth, &(chl->unknown_1)); /* 0x0000 0000 */
	prs_uint32("unknown_2", ps, depth, &(chl->unknown_2)); /* 0x0000 b2b3 */
	prs_uint32("neg_flags", ps, depth, &(chl->neg_flags)); /* 0x0000 82b1 */

	prs_uint8s (False, "challenge", ps, depth, chl->challenge, sizeof(chl->challenge));
	prs_uint8s (False, "reserved ", ps, depth, chl->reserved , sizeof(chl->reserved ));
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_RESP structure.

*** lkclXXXX FUDGE!  HAVE TO MANUALLY SPECIFY OFFSET HERE (0x1c bytes) ***
*** lkclXXXX the actual offset is at the start of the auth verifier    ***

********************************************************************/
void make_rpc_auth_ntlmssp_resp(RPC_AUTH_NTLMSSP_RESP *rsp,
				uchar lm_resp[24], uchar nt_resp[24],
				char *domain, char *user, char *wks,
				uint32 neg_flags)
{
	uint32 offset;
	int dom_len = strlen(domain);
	int wks_len = strlen(wks   );
	int usr_len = strlen(user  );
	int lm_len  = lm_resp != NULL ? 24 : 0;
	int nt_len  = nt_resp != NULL ? 24 : 0;

	DEBUG(5,("make_rpc_auth_ntlmssp_resp\n"));

	if (rsp == NULL) return;

#ifdef DEBUG_PASSWORD
	DEBUG(100,("lm_resp\n"));
	dump_data(100, lm_resp, 24);
	DEBUG(100,("nt_resp\n"));
	dump_data(100, nt_resp, 24);
#endif

	DEBUG(6,("dom: %s user: %s wks: %s neg_flgs: 0x%x\n",
	          domain, user, wks, neg_flags));

	offset = 0x40;

	if (IS_BITS_SET_ALL(neg_flags, NTLMSSP_NEGOTIATE_UNICODE))
	{
		dom_len *= 2;
		wks_len *= 2;
		usr_len *= 2;
	}

	make_str_hdr(&rsp->hdr_domain , dom_len, dom_len, offset);
	offset += dom_len;

	make_str_hdr(&rsp->hdr_usr    , usr_len, usr_len, offset);
	offset += usr_len;

	make_str_hdr(&rsp->hdr_wks    , wks_len, wks_len, offset);
	offset += wks_len;

	make_str_hdr(&rsp->hdr_lm_resp, lm_len , lm_len , offset);
	offset += lm_len;

	make_str_hdr(&rsp->hdr_nt_resp, nt_len , nt_len , offset);
	offset += nt_len;

	make_str_hdr(&rsp->hdr_sess_key, 0, 0, offset);

	rsp->neg_flags = neg_flags;

	memcpy(rsp->lm_resp, lm_resp, 24);
	memcpy(rsp->nt_resp, nt_resp, 24);

	if (IS_BITS_SET_ALL(neg_flags, NTLMSSP_NEGOTIATE_UNICODE))
	{
		struni2((uint16*)rsp->domain, domain);
		struni2((uint16*)rsp->user  , user  );
		struni2((uint16*)rsp->wks   , wks   );
	}
	else
	{
		fstrcpy(rsp->domain, domain);
		fstrcpy(rsp->user  , user  );
		fstrcpy(rsp->wks   , wks   );
	}
	rsp->sess_key[0] = 0;
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_RESP structure.

*** lkclXXXX FUDGE!  HAVE TO MANUALLY SPECIFY OFFSET HERE (0x1c bytes) ***
*** lkclXXXX the actual offset is at the start of the auth verifier    ***

********************************************************************/
void smb_io_rpc_auth_ntlmssp_resp(char *desc, RPC_AUTH_NTLMSSP_RESP *rsp, prs_struct *ps, int depth)
{
	if (rsp == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_resp");
	depth++;

	if (ps->io)
	{
		uint32 old_offset;

		/* reading */

		ZERO_STRUCTP(rsp);

		smb_io_strhdr("hdr_lm_resp ", &rsp->hdr_lm_resp , ps, depth); 
		smb_io_strhdr("hdr_nt_resp ", &rsp->hdr_nt_resp , ps, depth); 
		smb_io_strhdr("hdr_domain  ", &rsp->hdr_domain  , ps, depth); 
		smb_io_strhdr("hdr_user    ", &rsp->hdr_usr     , ps, depth); 
		smb_io_strhdr("hdr_wks     ", &rsp->hdr_wks     , ps, depth); 
		smb_io_strhdr("hdr_sess_key", &rsp->hdr_sess_key, ps, depth); 

		prs_uint32("neg_flags", ps, depth, &(rsp->neg_flags)); /* 0x0000 82b1 */

		old_offset = ps->offset;

		ps->offset = rsp->hdr_domain  .buffer + 0x1c;
		prs_uint8s(True , "domain  ", ps, depth, (uint8*)rsp->domain  , MIN(rsp->hdr_domain  .str_str_len, sizeof(rsp->domain  ))); 
		old_offset += rsp->hdr_domain  .str_str_len;

		ps->offset = rsp->hdr_usr     .buffer + 0x1c;
		prs_uint8s(True , "user    ", ps, depth, (uint8*)rsp->user    , MIN(rsp->hdr_usr     .str_str_len, sizeof(rsp->user    ))); 
		old_offset += rsp->hdr_usr     .str_str_len;

		ps->offset = rsp->hdr_wks     .buffer + 0x1c;
		prs_uint8s(True , "wks     ", ps, depth, (uint8*)rsp->wks     , MIN(rsp->hdr_wks     .str_str_len, sizeof(rsp->wks     ))); 
		old_offset += rsp->hdr_wks     .str_str_len;

		ps->offset = rsp->hdr_lm_resp .buffer + 0x1c;
		prs_uint8s(False, "lm_resp ", ps, depth, (uint8*)rsp->lm_resp , MIN(rsp->hdr_lm_resp .str_str_len, sizeof(rsp->lm_resp ))); 
		old_offset += rsp->hdr_lm_resp .str_str_len;

		ps->offset = rsp->hdr_nt_resp .buffer + 0x1c;
		prs_uint8s(False, "nt_resp ", ps, depth, (uint8*)rsp->nt_resp , MIN(rsp->hdr_nt_resp .str_str_len, sizeof(rsp->nt_resp ))); 
		old_offset += rsp->hdr_nt_resp .str_str_len;

		if (rsp->hdr_sess_key.str_str_len != 0)
		{
			ps->offset = rsp->hdr_sess_key.buffer + 0x1c;
			old_offset += rsp->hdr_sess_key.str_str_len;
			prs_uint8s(False, "sess_key", ps, depth, (uint8*)rsp->sess_key, MIN(rsp->hdr_sess_key.str_str_len, sizeof(rsp->sess_key))); 
		}

		ps->offset = old_offset;
	}
	else
	{
		/* writing */
		smb_io_strhdr("hdr_lm_resp ", &rsp->hdr_lm_resp , ps, depth); 
		smb_io_strhdr("hdr_nt_resp ", &rsp->hdr_nt_resp , ps, depth); 
		smb_io_strhdr("hdr_domain  ", &rsp->hdr_domain  , ps, depth); 
		smb_io_strhdr("hdr_user    ", &rsp->hdr_usr     , ps, depth); 
		smb_io_strhdr("hdr_wks     ", &rsp->hdr_wks     , ps, depth); 
		smb_io_strhdr("hdr_sess_key", &rsp->hdr_sess_key, ps, depth); 

		prs_uint32("neg_flags", ps, depth, &(rsp->neg_flags)); /* 0x0000 82b1 */

		prs_uint8s(True , "domain  ", ps, depth, (uint8*)rsp->domain  , MIN(rsp->hdr_domain  .str_str_len, sizeof(rsp->domain  ))); 
		prs_uint8s(True , "user    ", ps, depth, (uint8*)rsp->user    , MIN(rsp->hdr_usr     .str_str_len, sizeof(rsp->user    ))); 
		prs_uint8s(True , "wks     ", ps, depth, (uint8*)rsp->wks     , MIN(rsp->hdr_wks     .str_str_len, sizeof(rsp->wks     ))); 
		prs_uint8s(False, "lm_resp ", ps, depth, (uint8*)rsp->lm_resp , MIN(rsp->hdr_lm_resp .str_str_len, sizeof(rsp->lm_resp ))); 
		prs_uint8s(False, "nt_resp ", ps, depth, (uint8*)rsp->nt_resp , MIN(rsp->hdr_nt_resp .str_str_len, sizeof(rsp->nt_resp ))); 
		prs_uint8s(False, "sess_key", ps, depth, (uint8*)rsp->sess_key, MIN(rsp->hdr_sess_key.str_str_len, sizeof(rsp->sess_key))); 
	}
}

/*******************************************************************
checks an RPC_AUTH_NTLMSSP_CHK structure.
********************************************************************/
BOOL rpc_auth_ntlmssp_chk(RPC_AUTH_NTLMSSP_CHK *chk, uint32 crc32, uint32 seq_num)
{
	if (chk == NULL)
	{
		return False;
	}

	if (chk->crc32 != crc32 ||
	    chk->ver   != NTLMSSP_SIGN_VERSION ||
	    chk->seq_num != seq_num)
	{
		DEBUG(5,("verify failed - crc %x ver %x seq %d\n",
			crc32, NTLMSSP_SIGN_VERSION, seq_num));
		DEBUG(5,("verify expect - crc %x ver %x seq %d\n",
			chk->crc32, chk->ver, chk->seq_num));
		return False;
	}
	return True;
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_CHK structure.
********************************************************************/
void make_rpc_auth_ntlmssp_chk(RPC_AUTH_NTLMSSP_CHK *chk,
				uint32 ver, uint32 crc32, uint32 seq_num)
{
	if (chk == NULL) return;

	chk->ver      = ver     ;
	chk->reserved = 0x0;
	chk->crc32    = crc32   ;
	chk->seq_num  = seq_num ;
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_CHK structure.
********************************************************************/
void smb_io_rpc_auth_ntlmssp_chk(char *desc, RPC_AUTH_NTLMSSP_CHK *chk, prs_struct *ps, int depth)
{
	if (chk == NULL) return;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_chk");
	depth++;

	prs_uint32("ver     ", ps, depth, &(chk->ver     )); 
	prs_uint32("reserved", ps, depth, &(chk->reserved)); 
	prs_uint32("crc32   ", ps, depth, &(chk->crc32   )); 
	prs_uint32("seq_num ", ps, depth, &(chk->seq_num )); 
}

