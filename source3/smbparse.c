/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Luke Leighton 1996 - 1997  Paul Ashton 1997
   
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

#include "includes.h"

extern int DEBUGLEVEL;


/*******************************************************************
reads or writes a UTIME type.
********************************************************************/
char* smb_io_utime(BOOL io, UTIME *t, char *q, char *base, int align)
{
	if (t == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL (io, q, t->time, 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes an NTTIME structure.
********************************************************************/
char* smb_io_time(BOOL io, NTTIME *nttime, char *q, char *base, int align)
{
	if (nttime == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, nttime->low , 0); q += 4; /* low part */
	RW_IVAL(io, q, nttime->high, 0); q += 4; /* high part */

	return q;
}

/*******************************************************************
reads or writes a DOM_SID structure.
********************************************************************/
char* smb_io_dom_sid(BOOL io, DOM_SID *sid, char *q, char *base, int align)
{
	int i;

	if (sid == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_CVAL(io, q, sid->sid_no, 0); q++; 
	RW_CVAL(io, q, sid->num_auths, 0); q++;

	for (i = 0; i < 6; i++)
	{
		RW_CVAL(io, q, sid->id_auth[i], 0); q++;
	}

	/* oops! XXXX should really issue a warning here... */
	if (sid->num_auths > MAXSUBAUTHS) sid->num_auths = MAXSUBAUTHS;

	RW_PSVAL(io, q, sid->sub_auths, sid->num_auths); q += sid->num_auths * 2;

	return q;
}

/*******************************************************************
reads or writes a UNIHDR structure.
********************************************************************/
char* smb_io_unihdr(BOOL io, UNIHDR *hdr, char *q, char *base, int align)
{
	if (hdr == NULL) return NULL;

	/* should be value 4, so enforce it. */
	hdr->undoc = 4;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, hdr->uni_max_len, 0); q += 4;
	RW_IVAL(io, q, hdr->uni_str_len, 0); q += 4;
	RW_IVAL(io, q, hdr->undoc      , 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes a UNIHDR2 structure.
********************************************************************/
char* smb_io_unihdr2(BOOL io, UNIHDR2 *hdr2, char *q, char *base, int align)
{
	if (hdr2 == NULL) return NULL;

	q = align_offset(q, base, align);

	q = smb_io_unihdr(io, &(hdr2->unihdr), q, base, align);
	RW_IVAL(io, q, hdr2->undoc_buffer, 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes a UNISTR structure.
XXXX NOTE: UNISTR structures NEED to be null-terminated.
********************************************************************/
char* smb_io_unistr(BOOL io, UNISTR *uni, char *q, char *base, int align)
{
	if (uni == NULL) return NULL;

	q = align_offset(q, base, align);
	
	if (io)
	{
		/* io True indicates read _from_ the SMB buffer into the string */
		q += 2 * unistrcpy((char*)uni->buffer, q);
	}
	else
	{
		/* io True indicates copy _from_ the string into SMB buffer */
		q += 2 * unistrcpy(q, (char*)uni->buffer);
	}
	return q;
}

/*******************************************************************
reads or writes a UNISTR2 structure.
XXXX NOTE: UNISTR2 structures need NOT be null-terminated.
     the uni_str_len member tells you how long the string is;
     the uni_max_len member tells you how large the buffer is.
********************************************************************/
char* smb_io_unistr2(BOOL io, UNISTR2 *uni2, char *q, char *base, int align)
{
	if (uni2 == NULL) return NULL;

	q = align_offset(q, base, align);
	
	/* should be value 0, so enforce it. */
	uni2->undoc = 0;

	RW_IVAL(io, q, uni2->uni_max_len, 0); q += 4;
	RW_IVAL(io, q, uni2->undoc      , 0); q += 4;
	RW_IVAL(io, q, uni2->uni_str_len, 0); q += 4;

	/* oops! XXXX maybe issue a warning that this is happening... */
	if (uni2->uni_max_len > MAX_UNISTRLEN) uni2->uni_max_len = MAX_UNISTRLEN;
	if (uni2->uni_str_len > MAX_UNISTRLEN) uni2->uni_str_len = MAX_UNISTRLEN;

	/* buffer advanced by indicated length of string
       NOT by searching for null-termination */
	RW_PSVAL(io, q, uni2->buffer, uni2->uni_max_len); q += uni2->uni_max_len * 2;

	return q;
}

/*******************************************************************
reads or writes a DOM_SID2 structure.
********************************************************************/
char* smb_io_dom_sid2(BOOL io, DOM_SID2 *sid2, char *q, char *base, int align)
{
	if (sid2 == NULL) return NULL;

	q = align_offset(q, base, align);
	
	/* should be value 5, so enforce it */
	sid2->type = 5;

	/* should be value 0, so enforce it */
	sid2->undoc = 0;

	RW_IVAL(io, q, sid2->type , 0); q += 4;
	RW_IVAL(io, q, sid2->undoc, 0); q += 4;

	q = smb_io_unihdr2(io, &(sid2->hdr), q, base, align);
	q = smb_io_unistr (io, &(sid2->str), q, base, align);

	return q;
}

/*******************************************************************
reads or writes a DOM_RID2 structure.
********************************************************************/
char* smb_io_dom_rid2(BOOL io, DOM_RID2 *rid2, char *q, char *base, int align)
{
	if (rid2 == NULL) return NULL;

	q = align_offset(q, base, align);
	
	/* should be value 5, so enforce it */
	rid2->type = 5;

	/* should be value 5, so enforce it */
	rid2->undoc = 5;

	RW_IVAL(io, q, rid2->type, 0); q += 4;
	RW_IVAL(io, q, rid2->undoc   , 0); q += 4;
	RW_IVAL(io, q, rid2->rid     , 0); q += 4;
	RW_IVAL(io, q, rid2->rid_idx , 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes a DOM_LOG_INFO structure.
********************************************************************/
char* smb_io_log_info(BOOL io, DOM_LOG_INFO *log, char *q, char *base, int align)
{
	if (log == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, log->undoc_buffer, 0); q += 4;

	q = smb_io_unistr2(io, &(log->uni_logon_srv), q, base, align);
	q = smb_io_unistr2(io, &(log->uni_acct_name), q, base, align);

	RW_SVAL(io, q, log->sec_chan, 0); q += 2;

	/* XXXX no alignment required between sec_chan and uni_comp_name */
	q = smb_io_unistr2(io, &(log->uni_comp_name), q, base, 0);

	return q;
}

/*******************************************************************
reads or writes a DOM_CHAL structure.
********************************************************************/
char* smb_io_chal(BOOL io, DOM_CHAL *chal, char *q, char *base, int align)
{
	if (chal == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_PCVAL(io, q, chal->data, 8); q += 8;

	return q;
}

/*******************************************************************
reads or writes a DOM_CRED structure.
********************************************************************/
char* smb_io_cred(BOOL io, DOM_CRED *cred, char *q, char *base, int align)
{
	if (cred == NULL) return NULL;

	q = align_offset(q, base, align);
	
	q = smb_io_chal (io, &(cred->challenge), q, base, align);
	q = smb_io_utime(io, &(cred->timestamp), q, base, align);

	return q;
}

/*******************************************************************
reads or writes a DOM_CLNT_INFO structure.
********************************************************************/
char* smb_io_clnt_info(BOOL io, DOM_CLNT_INFO *clnt, char *q, char *base, int align)
{
	if (clnt == NULL) return NULL;

	q = align_offset(q, base, align);
	
	q = smb_io_log_info(io, &(clnt->login), q, base, align);
	q = smb_io_cred    (io, &(clnt->cred ), q, base, align);

	return q;
}

/*******************************************************************
reads or writes a DOM_LOGON_ID structure.
********************************************************************/
char* smb_io_logon_id(BOOL io, DOM_LOGON_ID *log, char *q, char *base, int align)
{
	if (log == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, log->low , 0); q += 4;
	RW_IVAL(io, q, log->high, 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes an ARC4_OWF structure.
********************************************************************/
char* smb_io_arc4_owf(BOOL io, ARC4_OWF *hash, char *q, char *base, int align)
{
	if (hash == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_PCVAL(io, q, hash->data, 16); q += 16;

	return q;
}

/*******************************************************************
reads or writes an DOM_ID_INFO_1 structure.
********************************************************************/
char* smb_io_id_info1(BOOL io, DOM_ID_INFO_1 *id, char *q, char *base, int align)
{
	if (id == NULL) return NULL;

	q = align_offset(q, base, align);
	
	q = smb_io_unihdr(io, &(id->hdr_domain_name   ), q, base, align);

	RW_IVAL(io, q, id->param, 0); q += 4;
	q = smb_io_logon_id(io, &(id->logon_id), q, base, align);

	q = smb_io_unihdr(io, &(id->hdr_user_name     ), q, base, align);
	q = smb_io_unihdr(io, &(id->hdr_workgroup_name), q, base, align);

	q = smb_io_arc4_owf(io, &(id->arc4_lm_owf), q, base, align);
	q = smb_io_arc4_owf(io, &(id->arc4_nt_owf), q, base, align);

	q = smb_io_unistr2(io, &(id->uni_domain_name   ), q, base, align);
	q = smb_io_unistr2(io, &(id->uni_user_name     ), q, base, align);
	q = smb_io_unistr2(io, &(id->uni_workgroup_name), q, base, align);

	return q;
}

/*******************************************************************
reads or writes a DOM_SAM_INFO structure.
********************************************************************/
char* smb_io_sam_info(BOOL io, DOM_SAM_INFO *sam, char *q, char *base, int align)
{
	if (sam == NULL) return NULL;

	q = align_offset(q, base, align);
	
	q = smb_io_clnt_info(io, &(sam->client  ), q, base, align);
	q = smb_io_cred     (io, &(sam->rtn_cred), q, base, align);

	RW_IVAL(io, q, sam->logon_level, 0); q += 4;
	RW_SVAL(io, q, sam->auth_level , 0); q += 4;

	switch (sam->auth_level)
	{
		case 1:
		{
			q = smb_io_id_info1(io, &(sam->auth.id1), q, base, align);
			break;
		}
		default:
		{
			/* PANIC! */
			break;
		}
	}
	return q;
}

/*******************************************************************
reads or writes a DOM_GID structure.
********************************************************************/
char* smb_io_gid(BOOL io, DOM_GID *gid, char *q, char *base, int align)
{
	if (gid == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, gid->gid , 0); q += 4;
	RW_IVAL(io, q, gid->attr, 0); q += 4;

	return q;
}

/*******************************************************************
reads or writes an RPC_HDR structure.
********************************************************************/
char* smb_io_rpc_hdr(BOOL io, RPC_HDR *rpc, char *q, char *base, int align)
{
	if (rpc == NULL) return NULL;

	/* reserved should be zero: enforce it */
	rpc->reserved = 0;

	RW_CVAL(io, q, rpc->major, 0); q++;
	RW_CVAL(io, q, rpc->minor, 0); q++;
	RW_CVAL(io, q, rpc->pkt_type, 0); q++;
	RW_CVAL(io, q, rpc->frag, 0); q++;
	RW_IVAL(io, q, rpc->pack_type, 0); q += 4;
	RW_SVAL(io, q, rpc->frag_len, 0); q += 2;
	RW_SVAL(io, q, rpc->auth_len, 0); q += 2;
	RW_IVAL(io, q, rpc->call_id, 0); q += 4;
	RW_IVAL(io, q, rpc->alloc_hint, 0); q += 4;
	RW_CVAL(io, q, rpc->context_id, 0); q++;
	RW_CVAL(io, q, rpc->reserved, 0); q++;

	return q;
}

/*******************************************************************
reads or writes an LSA_POL_HND structure.
********************************************************************/
char* smb_io_pol_hnd(BOOL io, LSA_POL_HND *pol, char *q, char *base, int align, int depth)
{
	if (pol == NULL) return NULL;

	DEBUG(5,("%ssmb_io_pol_hnd\n", tab_depth(depth)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_PCVAL("data", depth, base, io, q, pol->data, POL_HND_SIZE); q += POL_HND_SIZE;

	return q;
}

/*******************************************************************
reads or writes a dom query structure.
********************************************************************/
char* smb_io_dom_query_3(BOOL io, DOM_QUERY_3 *d_q, char *q, char *base, int align)
{
	return smb_io_dom_query(io, d_q, q, base, align);
}

/*******************************************************************
reads or writes a dom query structure.
********************************************************************/
char* smb_io_dom_query_5(BOOL io, DOM_QUERY_3 *d_q, char *q, char *base, int align)
{
	return smb_io_dom_query(io, d_q, q, base, align);
}

/*******************************************************************
reads or writes a dom query structure.
********************************************************************/
char* smb_io_dom_query(BOOL io, DOM_QUERY *d_q, char *q, char *base, int align)
{
	if (d_q == NULL) return NULL;

	q = align_offset(q, base, align);
	

	RW_SVAL(io, q, d_q->uni_dom_max_len, 0); q += 2; /* domain name string length * 2 */
	RW_SVAL(io, q, d_q->padding        , 0); q += 2; /* 2 padding bytes */
	RW_SVAL(io, q, d_q->uni_dom_str_len, 0); q += 2; /* domain name string length * 2 */

	RW_IVAL(io, q, d_q->buffer_dom_name, 0); q += 4; /* undocumented domain name string buffer pointer */
	RW_IVAL(io, q, d_q->buffer_dom_sid , 0); q += 4; /* undocumented domain SID string buffer pointer */

	if (d_q->buffer_dom_name != 0)
	{
		q = smb_io_unistr2(io, &(d_q->uni_domain_name), q, base, align); /* domain name (unicode string) */
	}
	if (d_q->buffer_dom_sid != 0)
	{
		q = smb_io_dom_sid(io, &(d_q->dom_sid), q, base, align); /* domain SID */
	}

	return q;
}

/*******************************************************************
reads or writes a DOM_R_REF structure.
********************************************************************/
char* smb_io_dom_r_ref(BOOL io, DOM_R_REF *r_r, char *q, char *base, int align)
{
	int i;

	if (r_r == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, r_r->undoc_buffer, 0); q += 4; /* undocumented buffer pointer. */
	RW_IVAL(io, q, r_r->num_ref_doms_1, 0); q += 4; /* num referenced domains? */
	RW_IVAL(io, q, r_r->buffer_dom_name, 0); q += 4; /* undocumented domain name buffer pointer. */
	RW_IVAL(io, q, r_r->max_entries, 0); q += 4; /* 32 - max number of entries */
	RW_IVAL(io, q, r_r->num_ref_doms_2, 0); q += 4; /* 4 - num referenced domains? */

	q = smb_io_unihdr2(io, &(r_r->hdr_dom_name), q, base, align); /* domain name unicode string header */

	for (i = 0; i < r_r->num_ref_doms_1-1; i++)
	{
		q = smb_io_unihdr2(io, &(r_r->hdr_ref_dom[i]), q, base, align);
	}

	q = smb_io_unistr(io, &(r_r->uni_dom_name), q, base, align); /* domain name unicode string */

	for (i = 0; i < r_r->num_ref_doms_2; i++)
	{
		q = smb_io_dom_sid(io, &(r_r->ref_dom[i]), q, base, align); /* referenced domain SIDs */
	}
	return q;
}

/*******************************************************************
reads or writes a DOM_NAME structure.
********************************************************************/
char* smb_io_dom_name(BOOL io, DOM_NAME *name, char *q, char *base, int align)
{
	if (name == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, name->uni_str_len, 0); q += 4;

	/* don't know if len is specified by uni_str_len member... */
	/* assume unicode string is unicode-null-terminated, instead */

	q = smb_io_unistr(io, &(name->str), q, base, align);

	return q;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* smb_io_neg_flags(BOOL io, NEG_FLAGS *neg, char *q, char *base, int align)
{
	if (neg == NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, neg->neg_flags, 0); q += 4;

	return q;
}


#if 0
/*******************************************************************
reads or writes a structure.
********************************************************************/
 char* smb_io_(BOOL io, *, char *q, char *base, int align)
{
	if (== NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, , 0); q += 4;

	return q;
}
#endif
