
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
 *  Copyright (C) Paul Ashton                  1997-1999.
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

#define SYNT_BROWSER_V0          \
{                                 \
	{                             \
		0x98, 0xd0, 0xff, 0x6b,   \
		0x12, 0xa1, 0x10, 0x36,   \
		0x98, 0x33, 0x01, 0x28,   \
		0x92, 0x02, 0x01, 0x62    \
	}, 0x00                       \
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

#define SYNT_ATSVC_V1            \
{                                 \
	{                             \
		0x82, 0x06, 0xf7, 0x1f,   \
		0x51, 0x0a, 0xe8, 0x30,   \
		0x07, 0x6d, 0x74, 0x0b,   \
		0xe8, 0xce, 0xe9, 0x8b    \
	}, 0x01                       \
}                                 \

#define SYNT_SPOOLSS_V1           \
{                                 \
	{                             \
		0x78, 0x56, 0x34, 0x12,   \
		0x34, 0x12, 0xcd, 0xab,   \
		0xef, 0x00, 0x01, 0x23,   \
		0x45, 0x67, 0x89, 0xab    \
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

#define SYNT_EVENTLOG_V0            \
{                                 \
	{                             \
		0xdc, 0x3f, 0x27, 0x82,   \
		0x2a, 0xe3, 0xc3, 0x18,   \
		0x3f, 0x78, 0x82, 0x79,   \
		0x29, 0xdc, 0x23, 0xea    \
	}, 0x00                       \
}
                                 \
struct pipe_id_info pipe_names [] =
{
	/* client pipe , abstract syntax , server pipe   , transfer syntax */
	{ PIPE_LSARPC  , SYNT_LSARPC_V0  , PIPE_LSASS    , TRANS_SYNT_V2 },
	{ PIPE_BROWSER , SYNT_BROWSER_V0 , PIPE_NTSVCS   , TRANS_SYNT_V2 },
	{ PIPE_SAMR    , SYNT_SAMR_V1    , PIPE_LSASS    , TRANS_SYNT_V2 },
	{ PIPE_NETLOGON, SYNT_NETLOGON_V1, PIPE_LSASS    , TRANS_SYNT_V2 },
	{ PIPE_SRVSVC  , SYNT_SRVSVC_V3  , PIPE_NTSVCS   , TRANS_SYNT_V2 },
	{ PIPE_SVCCTL  , SYNT_SVCCTL_V2  , PIPE_NTSVCS   , TRANS_SYNT_V2 },
	{ PIPE_WKSSVC  , SYNT_WKSSVC_V1  , PIPE_NTSVCS   , TRANS_SYNT_V2 },
	{ PIPE_WINREG  , SYNT_WINREG_V1  , PIPE_WINREG   , TRANS_SYNT_V2 },
	{ PIPE_ATSVC   , SYNT_ATSVC_V1   , PIPE_ATSVC    , TRANS_SYNT_V2 },
	{ PIPE_SPOOLSS , SYNT_SPOOLSS_V1 , PIPE_SPOOLSS  , TRANS_SYNT_V2 },
	{ PIPE_EVENTLOG, SYNT_EVENTLOG_V0, PIPE_EVENTLOG , TRANS_SYNT_V2 },
	{ NULL         , SYNT_NONE_V0    , NULL          , SYNT_NONE_V0  }
};

/*******************************************************************
creates an RPC_HDR structure.
********************************************************************/
BOOL make_rpc_hdr(RPC_HDR *hdr, enum RPC_PKT_TYPE pkt_type, uint8 flags,
				uint32 call_id, int data_len, int auth_len)
{
	if (hdr == NULL) return False;

	hdr->major        = 5;               /* RPC version 5 */
	hdr->minor        = 0;               /* minor version 0 */
	hdr->pkt_type     = pkt_type;        /* RPC packet type */
	hdr->flags        = flags;           /* dce/rpc flags */
	hdr->pack_type    = 0x10;            /* packed data representation */
	hdr->frag_len     = data_len;        /* fragment length, fill in later */
	hdr->auth_len     = auth_len;        /* authentication length */
	hdr->call_id      = call_id;         /* call identifier - match incoming RPC */

	return True;
}

/*******************************************************************
reads or writes an RPC_HDR structure.
********************************************************************/
BOOL smb_io_rpc_hdr(char *desc,  RPC_HDR *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return False;

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

	return True;
}

/*******************************************************************
checks a PDU structure.
********************************************************************/
BOOL is_complete_pdu(prs_struct *ps)
{
	RPC_HDR hdr;
	int len = ps->data_size;

	DEBUG(10,("is_complete_pdu - len %d\n", len));
	ps->offset = 0x0;

	if (!ps->io)
	{
		/* writing.  oops!! */
		DEBUG(4,("is_complete_pdu: write set, not read!\n"));
		return False;
	}
		
	if (!smb_io_rpc_hdr("hdr", &hdr, ps, 0))
	{
		return False;
	}

	DEBUG(10,("is_complete_pdu - frag_len %d\n", hdr.frag_len));

	/* check that the fragment length is equal to the data length so far */
	return hdr.frag_len == len;
}

/*******************************************************************
reads or writes an RPC_HDR_FAULT structure.
********************************************************************/
BOOL smb_io_rpc_hdr_fault(char *desc,  RPC_HDR_FAULT *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_fault");
	depth++;

	prs_uint32("status  ", ps, depth, &(rpc->status  ));
	prs_uint32("reserved", ps, depth, &(rpc->reserved));

	return True;
}

/*******************************************************************
reads or writes an RPC_IFACE structure.
********************************************************************/
static BOOL smb_io_rpc_iface(char *desc,  RPC_IFACE *ifc, prs_struct *ps, int depth)
{
	if (ifc == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_iface");
	depth++;

	prs_align(ps);

	prs_uint8s (False, "data   ", ps, depth, ifc->data, sizeof(ifc->data));
	prs_uint32 (       "version", ps, depth, &(ifc->version));

	return True;
}

/*******************************************************************
creates an RPC_ADDR_STR structure.

The name can be null (RPC Alter-Context)
********************************************************************/
static BOOL make_rpc_addr_str(RPC_ADDR_STR *str, const char *name)
{
	if (str == NULL ) return False;
	if (name == NULL)
	{
		str->len = 1;
		fstrcpy(str->str, "");
	}
	else
	{
		str->len = strlen(name) + 1;
		fstrcpy(str->str, name);
	}

	return True;
}

/*******************************************************************
reads or writes an RPC_ADDR_STR structure.
********************************************************************/
static BOOL smb_io_rpc_addr_str(char *desc,  RPC_ADDR_STR *str, prs_struct *ps, int depth)
{
	if (str == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_addr_str");
	depth++;
	prs_align(ps);

	prs_uint16 (      "len", ps, depth, &(str->len));
	prs_uint8s (True, "str", ps, depth, (uchar*)str->str, str->len);

	return True;
}

/*******************************************************************
creates an RPC_HDR_BBA structure.
********************************************************************/
static BOOL make_rpc_hdr_bba(RPC_HDR_BBA *bba, uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid)
{
	if (bba == NULL) return False;

	bba->max_tsize = max_tsize; /* maximum transmission fragment size (0x1630) */
	bba->max_rsize = max_rsize; /* max receive fragment size (0x1630) */   
	bba->assoc_gid = assoc_gid; /* associated group id (0x0) */ 

	return True;
}

/*******************************************************************
reads or writes an RPC_HDR_BBA structure.
********************************************************************/
static BOOL smb_io_rpc_hdr_bba(char *desc,  RPC_HDR_BBA *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_bba");
	depth++;

	prs_uint16("max_tsize", ps, depth, &(rpc->max_tsize));
	prs_uint16("max_rsize", ps, depth, &(rpc->max_rsize));
	prs_uint32("assoc_gid", ps, depth, &(rpc->assoc_gid));

	return True;
}

/*******************************************************************
creates an RPC_HDR_RB structure.
********************************************************************/
BOOL make_rpc_hdr_rb(RPC_HDR_RB *rpc, 
				uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid,
				uint32 num_elements, uint16 context_id, uint8 num_syntaxes,
				RPC_IFACE *abstract, RPC_IFACE *transfer)
{
	if (rpc == NULL) return False;

	make_rpc_hdr_bba(&(rpc->bba), max_tsize, max_rsize, assoc_gid);

	rpc->num_elements = num_elements ; /* the number of elements (0x1) */
	rpc->context_id   = context_id   ; /* presentation context identifier (0x0) */
	rpc->num_syntaxes = num_syntaxes ; /* the number of syntaxes (has always been 1?)(0x1) */

	/* num and vers. of interface client is using */
	memcpy(&(rpc->abstract), abstract, sizeof(rpc->abstract));

	/* num and vers. of interface to use for replies */
	memcpy(&(rpc->transfer), transfer, sizeof(rpc->transfer));

	return True;
}

/*******************************************************************
reads or writes an RPC_HDR_RB structure.
********************************************************************/
BOOL smb_io_rpc_hdr_rb(char *desc,  RPC_HDR_RB *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_rb");
	depth++;

	smb_io_rpc_hdr_bba("", &(rpc->bba), ps, depth);

	prs_uint32("num_elements", ps, depth, &(rpc->num_elements));
	prs_uint16("context_id  ", ps, depth, &(rpc->context_id  ));
	prs_uint8 ("num_syntaxes", ps, depth, &(rpc->num_syntaxes));

	smb_io_rpc_iface("", &(rpc->abstract), ps, depth);
	smb_io_rpc_iface("", &(rpc->transfer), ps, depth);

	return True;
}

/*******************************************************************
creates an RPC_RESULTS structure.

lkclXXXX only one reason at the moment!

********************************************************************/
static BOOL make_rpc_results(RPC_RESULTS *res, 
				uint8 num_results, uint16 result, uint16 reason)
{
	if (res == NULL) return False;

	res->num_results = num_results; /* the number of results (0x01) */
	res->result      = result     ;  /* result (0x00 = accept) */
	res->reason      = reason     ;  /* reason (0x00 = no reason specified) */

	return True;
}

/*******************************************************************
reads or writes an RPC_RESULTS structure.

lkclXXXX only one reason at the moment!

********************************************************************/
static BOOL smb_io_rpc_results(char *desc,  RPC_RESULTS *res, prs_struct *ps, int depth)
{
	if (res == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_results");
	depth++;

	prs_align(ps);
	
	prs_uint8 ("num_results", ps, depth, &(res->num_results));

	prs_align(ps);
	
	prs_uint16("result     ", ps, depth, &(res->result     ));
	prs_uint16("reason     ", ps, depth, &(res->reason     ));

	return True;
}

/*******************************************************************
creates an RPC_HDR_BA structure.

lkclXXXX only one reason at the moment!
jfm: nope two ! The pipe_addr can be NULL !

********************************************************************/
BOOL make_rpc_hdr_ba(RPC_HDR_BA *rpc, 
				uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid,
				const char *pipe_addr,
				uint8 num_results, uint16 result, uint16 reason,
				RPC_IFACE *transfer)
{
	if (rpc == NULL || transfer == NULL) return False;

	make_rpc_hdr_bba (&(rpc->bba ), max_tsize, max_rsize, assoc_gid);
	make_rpc_addr_str(&(rpc->addr), pipe_addr);
	make_rpc_results (&(rpc->res ), num_results, result, reason);

	/* the transfer syntax from the request */
	memcpy(&(rpc->transfer), transfer, sizeof(rpc->transfer));

	return True;
}

/*******************************************************************
reads or writes an RPC_HDR_BA structure.
********************************************************************/
BOOL smb_io_rpc_hdr_ba(char *desc,  RPC_HDR_BA *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_ba");
	depth++;

	smb_io_rpc_hdr_bba ("", &(rpc->bba)     , ps, depth);
	smb_io_rpc_addr_str("", &(rpc->addr)    , ps, depth);
	smb_io_rpc_results ("", &(rpc->res)     , ps, depth);
	smb_io_rpc_iface   ("", &(rpc->transfer), ps, depth);

	return True;
}

/*******************************************************************
creates an RPC_HDR_REQ structure.
********************************************************************/
BOOL make_rpc_hdr_req(RPC_HDR_REQ *hdr, uint32 alloc_hint, uint16 opnum)
{
	if (hdr == NULL) return False;

	hdr->alloc_hint   = alloc_hint; /* allocation hint */
	hdr->context_id   = 0;         /* presentation context identifier */
	hdr->opnum        = opnum;     /* opnum */

	return True;
}

/*******************************************************************
reads or writes an RPC_HDR_REQ structure.
********************************************************************/
BOOL smb_io_rpc_hdr_req(char *desc,  RPC_HDR_REQ *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_req");
	depth++;

	prs_uint32("alloc_hint", ps, depth, &(rpc->alloc_hint));
	prs_uint16("context_id", ps, depth, &(rpc->context_id));
	prs_uint16("opnum     ", ps, depth, &(rpc->opnum));

	return True;
}

/*******************************************************************
reads or writes an RPC_HDR_RESP structure.
********************************************************************/
BOOL smb_io_rpc_hdr_resp(char *desc,  RPC_HDR_RESP *rpc, prs_struct *ps, int depth)
{
	if (rpc == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_resp");
	depth++;

	prs_uint32("alloc_hint", ps, depth, &(rpc->alloc_hint));
	prs_uint16("context_id", ps, depth, &(rpc->context_id));
	prs_uint8 ("cancel_ct ", ps, depth, &(rpc->cancel_count));
	prs_uint8 ("reserved  ", ps, depth, &(rpc->reserved));

	return True;
}

/*******************************************************************
creates an RPC_HDR_AUTHA structure.
********************************************************************/
BOOL make_rpc_hdr_autha(RPC_HDR_AUTHA *rai,
				uint16 max_tsize, uint16 max_rsize,
				uint8 auth_type, uint8 auth_level,
				uint8 stub_type_len)
{
	if (rai == NULL) return False;

	rai->max_tsize = max_tsize; /* maximum transmission fragment size (0x1630) */
	rai->max_rsize = max_rsize; /* max receive fragment size (0x1630) */   

	rai->auth_type     = auth_type; /* nt lm ssp 0x0a */
	rai->auth_level    = auth_level; /* 0x06 */
	rai->stub_type_len = stub_type_len; /* 0x00 */
	rai->padding       = 0; /* padding 0x00 */

	rai->unknown       = 0x0014a0c0; /* non-zero pointer to something */

	return True;
}

/*******************************************************************
reads or writes an RPC_HDR_AUTHA structure.
********************************************************************/
BOOL smb_io_rpc_hdr_autha(char *desc, RPC_HDR_AUTHA *rai, prs_struct *ps, int depth)
{
	if (rai == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_autha");
	depth++;

	prs_uint16("max_tsize    ", ps, depth, &(rai->max_tsize));
	prs_uint16("max_rsize    ", ps, depth, &(rai->max_rsize));

	prs_uint8 ("auth_type    ", ps, depth, &(rai->auth_type    )); /* 0x0a nt lm ssp */
	prs_uint8 ("auth_level   ", ps, depth, &(rai->auth_level   ));/* 0x06 */
	prs_uint8 ("stub_type_len", ps, depth, &(rai->stub_type_len));
	prs_uint8 ("padding      ", ps, depth, &(rai->padding      ));

	prs_uint32("unknown      ", ps, depth, &(rai->unknown      )); /* 0x0014a0c0 */

	return True;
}

/*******************************************************************
creates an RPC_HDR_AUTH structure.
********************************************************************/
BOOL make_rpc_hdr_auth(RPC_HDR_AUTH *rai,
				uint8 auth_type, uint8 auth_level,
				uint8 stub_type_len,
				uint32 ptr)
{
	if (rai == NULL) return False;

	rai->auth_type     = auth_type; /* nt lm ssp 0x0a */
	rai->auth_level    = auth_level; /* 0x06 */
	rai->stub_type_len = stub_type_len; /* 0x00 */
	rai->padding       = 0; /* padding 0x00 */

	rai->unknown       = ptr; /* non-zero pointer to something */

	return True;
}

/*******************************************************************
reads or writes an RPC_HDR_AUTH structure.
********************************************************************/
BOOL smb_io_rpc_hdr_auth(char *desc, RPC_HDR_AUTH *rai, prs_struct *ps, int depth)
{
	if (rai == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_hdr_auth");
	depth++;

	prs_uint8 ("auth_type    ", ps, depth, &(rai->auth_type    )); /* 0x0a nt lm ssp */
	prs_uint8 ("auth_level   ", ps, depth, &(rai->auth_level   ));/* 0x06 */
	prs_uint8 ("stub_type_len", ps, depth, &(rai->stub_type_len));
	prs_uint8 ("padding      ", ps, depth, &(rai->padding      ));

	prs_uint32("unknown      ", ps, depth, &(rai->unknown      )); /* 0x0014a0c0 */

	return True;
}

/*******************************************************************
creates an RPC_AUTH_VERIFIER structure.
********************************************************************/
BOOL make_rpc_auth_verifier(RPC_AUTH_VERIFIER *rav,
				char *signature, uint32 msg_type)
{
	if (rav == NULL) return False;

	fstrcpy(rav->signature, signature); 
	rav->msg_type = msg_type;

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_VERIFIER structure.
********************************************************************/
BOOL smb_io_rpc_auth_verifier(char *desc, RPC_AUTH_VERIFIER *rav, prs_struct *ps, int depth)
{
	if (rav == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_verifier");
	depth++;

	prs_string("signature", ps, depth, rav->signature, 0, sizeof(rav->signature));
	prs_align(ps);
	prs_uint32("msg_type ", ps, depth, &(rav->msg_type  )); 

	return True;
}
