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
char* smb_io_utime(BOOL io, UTIME *t, char *q, char *base, int align, int depth)
{
	if (t == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_utime\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL ("time", depth, base, io, q, t->time); q += 4;

	return q;
}

/*******************************************************************
reads or writes an NTTIME structure.
********************************************************************/
char* smb_io_time(BOOL io, NTTIME *nttime, char *q, char *base, int align, int depth)
{
	if (nttime == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_time\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("low ", depth, base, io, q, nttime->low ); q += 4; /* low part */
	DBG_RW_IVAL("high", depth, base, io, q, nttime->high); q += 4; /* high part */

	return q;
}

/*******************************************************************
creates a DOM_SID structure.

BIG NOTE: this function only does SIDS where the identauth is not >= 2^32 
identauth >= 2^32 can be detected because it will be specified in hex

********************************************************************/
void make_dom_sid(DOM_SID *sid, char *domsid)
{
	int identauth;
	char *p;

	if (sid == NULL) return;

	if (domsid == NULL)
	{
		DEBUG(4,("netlogon domain SID: none\n"));
		sid->sid_rev_num = 0;
		sid->num_auths = 0;
		return;
	}
		
	DEBUG(4,("netlogon domain SID: %s\n", domsid));

	/* assume, but should check, that domsid starts "S-" */
	p = strtok(domsid+2,"-");
	sid->sid_rev_num = atoi(p);

	/* identauth in decimal should be <  2^32 */
	/* identauth in hex     should be >= 2^32 */
	identauth = atoi(strtok(0,"-"));

	DEBUG(4,("netlogon rev %d\n", sid->sid_rev_num));
	DEBUG(4,("netlogon %s ia %d\n", p, identauth));

	sid->id_auth[0] = 0;
	sid->id_auth[1] = 0;
	sid->id_auth[2] = (identauth & 0xff000000) >> 24;
	sid->id_auth[3] = (identauth & 0x00ff0000) >> 16;
	sid->id_auth[4] = (identauth & 0x0000ff00) >> 8;
	sid->id_auth[5] = (identauth & 0x000000ff);

	sid->num_auths = 0;

	while ((p = strtok(0, "-")) != NULL)
	{
		sid->sub_auths[sid->num_auths++] = atoi(p);
	}
}

/*******************************************************************
reads or writes a DOM_SID structure.
********************************************************************/
char* smb_io_dom_sid(BOOL io, DOM_SID *sid, char *q, char *base, int align, int depth)
{
	int i;

	if (sid == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_dom_sid\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("num_auths  ", depth, base, io, q, sid->num_auths); q += 4;
	DBG_RW_CVAL("sid_rev_num", depth, base, io, q, sid->sid_rev_num); q++; 
	DBG_RW_CVAL("num_auths  ", depth, base, io, q, sid->num_auths); q++;

	for (i = 0; i < 6; i++)
	{
		fstring tmp;
		sprintf(tmp, "id_auth[%d] ", i);
		DBG_RW_CVAL(tmp, depth, base, io, q, sid->id_auth[i]); q++;
	}

	/* oops! XXXX should really issue a warning here... */
	if (sid->num_auths > MAXSUBAUTHS) sid->num_auths = MAXSUBAUTHS;

	DBG_RW_PIVAL("num_auths ", depth, base, io, q, sid->sub_auths, sid->num_auths); q += sid->num_auths * 4;

	return q;
}

/*******************************************************************
creates a UNIHDR structure.
********************************************************************/
void make_uni_hdr(UNIHDR *hdr, int max_len, int len, uint16 terminate)
{
	hdr->uni_max_len = 2 * max_len;
	hdr->uni_str_len = 2 * len;
	hdr->undoc       = terminate;
}

/*******************************************************************
reads or writes a UNIHDR structure.
********************************************************************/
char* smb_io_unihdr(BOOL io, UNIHDR *hdr, char *q, char *base, int align, int depth)
{
	if (hdr == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_unihdr\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_SVAL("uni_str_len", depth, base, io, q, hdr->uni_str_len); q += 2;
	DBG_RW_SVAL("uni_max_len", depth, base, io, q, hdr->uni_max_len); q += 2;
	DBG_RW_IVAL("undoc      ", depth, base, io, q, hdr->undoc      ); q += 4;

	/* oops! XXXX maybe issue a warning that this is happening... */
	if (hdr->uni_max_len > MAX_UNISTRLEN) hdr->uni_max_len = MAX_UNISTRLEN;
	if (hdr->uni_str_len > MAX_UNISTRLEN) hdr->uni_str_len = MAX_UNISTRLEN;

	return q;
}

/*******************************************************************
creates a UNIHDR2 structure.
********************************************************************/
void make_uni_hdr2(UNIHDR2 *hdr, int max_len, int len, uint16 terminate)
{
	make_uni_hdr(&(hdr->unihdr), max_len, len, terminate);
	hdr->undoc_buffer = len > 0 ? 1 : 0;
}

/*******************************************************************
reads or writes a UNIHDR2 structure.
********************************************************************/
char* smb_io_unihdr2(BOOL io, UNIHDR2 *hdr2, char *q, char *base, int align, int depth)
{
	if (hdr2 == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_unihdr2\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_unihdr(io, &(hdr2->unihdr), q, base, align, depth);
	DBG_RW_IVAL("undoc_buffer", depth, base, io, q, hdr2->undoc_buffer); q += 4;

	return q;
}

/*******************************************************************
creates a UNISTR structure.
********************************************************************/
void make_unistr(UNISTR *str, char *buf)
{
	/* store the string (null-terminated copy) */
	PutUniCode((char *)(str->buffer), buf);
}

/*******************************************************************
reads or writes a UNISTR structure.
XXXX NOTE: UNISTR structures NEED to be null-terminated.
********************************************************************/
char* smb_io_unistr(BOOL io, UNISTR *uni, char *q, char *base, int align, int depth)
{
	if (uni == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_unistr\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

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
creates a UNISTR2 structure.
********************************************************************/
void make_unistr2(UNISTR2 *str, char *buf, int len)
{
	/* set up string lengths. add one if string is not null-terminated */
	str->uni_max_len = len;
	str->undoc       = 0;
	str->uni_str_len = len;

	/* store the string (null-terminated copy) */
	PutUniCode((char *)str->buffer, buf);
}

/*******************************************************************
reads or writes a UNISTR2 structure.
XXXX NOTE: UNISTR2 structures need NOT be null-terminated.
     the uni_str_len member tells you how long the string is;
     the uni_max_len member tells you how large the buffer is.
********************************************************************/
char* smb_io_unistr2(BOOL io, UNISTR2 *uni2, char *q, char *base, int align, int depth)
{
	if (uni2 == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_unistr2\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	/* should be value 0, so enforce it. */
	uni2->undoc = 0;

	DBG_RW_IVAL("uni_max_len", depth, base, io, q, uni2->uni_max_len); q += 4;
	DBG_RW_IVAL("undoc      ", depth, base, io, q, uni2->undoc      ); q += 4;
	DBG_RW_IVAL("uni_str_len", depth, base, io, q, uni2->uni_str_len); q += 4;

	/* oops! XXXX maybe issue a warning that this is happening... */
	if (uni2->uni_max_len > MAX_UNISTRLEN) uni2->uni_max_len = MAX_UNISTRLEN;
	if (uni2->uni_str_len > MAX_UNISTRLEN) uni2->uni_str_len = MAX_UNISTRLEN;

	/* buffer advanced by indicated length of string
       NOT by searching for null-termination */
	DBG_RW_PSVAL("buffer    ", depth, base, io, q, uni2->buffer, uni2->uni_max_len); q += uni2->uni_max_len * 2;

	return q;
}

/*******************************************************************
creates a DOM_SID2 structure.
********************************************************************/
void make_dom_sid2(DOM_SID2 *sid2, char *sid_str)
{
	int len_sid_str = strlen(sid_str);

	sid2->type = 0x5;
	sid2->undoc = 0;
	make_uni_hdr2(&(sid2->hdr), len_sid_str, len_sid_str, 0);
	make_unistr  (&(sid2->str), sid_str);
}

/*******************************************************************
reads or writes a DOM_SID2 structure.
********************************************************************/
char* smb_io_dom_sid2(BOOL io, DOM_SID2 *sid2, char *q, char *base, int align, int depth)
{
	if (sid2 == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_dom_sid2\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	/* should be value 5, so enforce it */
	sid2->type = 5;

	/* should be value 0, so enforce it */
	sid2->undoc = 0;

	DBG_RW_IVAL("type ", depth, base, io, q, sid2->type ); q += 4;
	DBG_RW_IVAL("undoc", depth, base, io, q, sid2->undoc); q += 4;

	q = smb_io_unihdr2(io, &(sid2->hdr), q, base, align, depth);
	q = smb_io_unistr (io, &(sid2->str), q, base, align, depth);

	return q;
}

/*******************************************************************
creates a DOM_RID2 structure.
********************************************************************/
void make_dom_rid2(DOM_RID2 *rid2, uint32 rid)
{
	rid2->type    = 0x5;
	rid2->undoc   = 0x5;
	rid2->rid     = rid;
	rid2->rid_idx = 0;
}

/*******************************************************************
reads or writes a DOM_RID2 structure.
********************************************************************/
char* smb_io_dom_rid2(BOOL io, DOM_RID2 *rid2, char *q, char *base, int align, int depth)
{
	if (rid2 == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_dom_rid2\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	/* should be value 5, so enforce it */
	rid2->type = 5;

	/* should be value 5, so enforce it */
	rid2->undoc = 5;

	DBG_RW_IVAL("type   ", depth, base, io, q, rid2->type); q += 4;
	DBG_RW_IVAL("undoc  ", depth, base, io, q, rid2->undoc   ); q += 4;
	DBG_RW_IVAL("rid    ", depth, base, io, q, rid2->rid     ); q += 4;
	DBG_RW_IVAL("rid_idx", depth, base, io, q, rid2->rid_idx ); q += 4;

	return q;
}

/*******************************************************************
makes a DOM_CLNT_SRV structure.
********************************************************************/
void make_clnt_srv(DOM_CLNT_SRV *log, char *logon_srv, char *comp_name)
{
	if (log == NULL) return;

	DEBUG(5,("make_clnt_srv: %d\n", __LINE__));

	if (logon_srv != NULL)
	{
		log->undoc_buffer = 1;
		make_unistr2(&(log->uni_logon_srv), logon_srv, strlen(logon_srv));
	}
	else
	{
		log->undoc_buffer = 1;
	}

	if (comp_name != NULL)
	{
		log->undoc_buffer2 = 1;
		make_unistr2(&(log->uni_comp_name), comp_name, strlen(comp_name));
	}
	else
	{
		log->undoc_buffer2 = 1;
	}
}

/*******************************************************************
reads or writes a DOM_CLNT_SRV structure.
********************************************************************/
char* smb_io_clnt_srv(BOOL io, DOM_CLNT_SRV *log, char *q, char *base, int align, int depth)
{
	if (log == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_clnt_srv\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("undoc_buffer ", depth, base, io, q, log->undoc_buffer ); q += 4;
	q = smb_io_unistr2(io, &(log->uni_logon_srv), q, base, align, depth);

	DBG_RW_IVAL("undoc_buffer2", depth, base, io, q, log->undoc_buffer2); q += 4;
	q = smb_io_unistr2(io, &(log->uni_comp_name), q, base, align, depth);

	return q;
}

/*******************************************************************
makes a DOM_LOG_INFO structure.
********************************************************************/
void make_log_info(DOM_LOG_INFO *log, char *logon_srv, char *acct_name,
		uint16 sec_chan, char *comp_name)
{
	if (log == NULL) return;

	DEBUG(5,("make_log_info %d\n", __LINE__));

	log->undoc_buffer = 1;

	make_unistr2(&(log->uni_logon_srv), logon_srv, strlen(logon_srv));
	make_unistr2(&(log->uni_acct_name), acct_name, strlen(acct_name));

	log->sec_chan = sec_chan;

	make_unistr2(&(log->uni_comp_name), comp_name, strlen(comp_name));
}

/*******************************************************************
reads or writes a DOM_LOG_INFO structure.
********************************************************************/
char* smb_io_log_info(BOOL io, DOM_LOG_INFO *log, char *q, char *base, int align, int depth)
{
	if (log == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_log_info\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("undoc_buffer", depth, base, io, q, log->undoc_buffer); q += 4;

	q = smb_io_unistr2(io, &(log->uni_logon_srv), q, base, align, depth);
	q = smb_io_unistr2(io, &(log->uni_acct_name), q, base, align, depth);

	DBG_RW_SVAL("sec_chan", depth, base, io, q, log->sec_chan); q += 2;

	q = smb_io_unistr2(io, &(log->uni_comp_name), q, base, align, depth);

	return q;
}

/*******************************************************************
reads or writes a DOM_CHAL structure.
********************************************************************/
char* smb_io_chal(BOOL io, DOM_CHAL *chal, char *q, char *base, int align, int depth)
{
	if (chal == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_chal\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("data[0]", depth, base, io, q, chal->data[0]); q += 4;
	DBG_RW_IVAL("data[1]", depth, base, io, q, chal->data[1]); q += 4;
/*
	DBG_RW_PCVAL("data", depth, base, io, q, chal->data, 8); q += 8;
*/
	return q;
}

/*******************************************************************
reads or writes a DOM_CRED structure.
********************************************************************/
char* smb_io_cred(BOOL io, DOM_CRED *cred, char *q, char *base, int align, int depth)
{
	if (cred == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_cred\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	q = smb_io_chal (io, &(cred->challenge), q, base, align, depth);
	q = smb_io_utime(io, &(cred->timestamp), q, base, align, depth);

	return q;
}

/*******************************************************************
makes a DOM_CLNT_INFO2 structure.
********************************************************************/
void make_clnt_info2(DOM_CLNT_INFO2 *clnt,
				char *logon_srv, char *comp_name,
				DOM_CRED *clnt_cred)
{
	if (clnt == NULL) return;

	DEBUG(5,("make_clnt_info: %d\n", __LINE__));

	make_clnt_srv(&(clnt->login), logon_srv, comp_name);

	if (clnt_cred != NULL)
	{
		clnt->ptr_cred = 1;
		memcpy(&(clnt->cred), clnt_cred, sizeof(clnt->cred));
	}
	else
	{
		clnt->ptr_cred = 0;
	}
}

/*******************************************************************
reads or writes a DOM_CLNT_INFO2 structure.
********************************************************************/
char* smb_io_clnt_info2(BOOL io, DOM_CLNT_INFO2 *clnt, char *q, char *base, int align, int depth)
{
	if (clnt == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_clnt_info2\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	q = smb_io_clnt_srv(io, &(clnt->login), q, base, align, depth);

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("ptr_cred", depth, base, io, q, clnt->ptr_cred); q += 4;
	q = smb_io_cred    (io, &(clnt->cred ), q, base, align, depth);

	return q;
}

/*******************************************************************
reads or writes a DOM_CLNT_INFO structure.
********************************************************************/
char* smb_io_clnt_info(BOOL io, DOM_CLNT_INFO *clnt, char *q, char *base, int align, int depth)
{
	if (clnt == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_clnt_info\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	q = smb_io_log_info(io, &(clnt->login), q, base, align, depth);
	q = smb_io_cred    (io, &(clnt->cred ), q, base, align, depth);

	return q;
}

/*******************************************************************
makes a DOM_LOGON_ID structure.
********************************************************************/
void make_logon_id(DOM_LOGON_ID *log, uint32 log_id_low, uint32 log_id_high)
{
	if (log == NULL) return;

	DEBUG(5,("make_logon_id: %d\n", __LINE__));

	log->low  = log_id_low;
	log->high = log_id_high;
}

/*******************************************************************
reads or writes a DOM_LOGON_ID structure.
********************************************************************/
char* smb_io_logon_id(BOOL io, DOM_LOGON_ID *log, char *q, char *base, int align, int depth)
{
	if (log == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_logon_id\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("low ", depth, base, io, q, log->low ); q += 4;
	DBG_RW_IVAL("high", depth, base, io, q, log->high); q += 4;

	return q;
}

/*******************************************************************
makes an ARC4_OWF structure.
********************************************************************/
void make_arc4_owf(ARC4_OWF *hash, char data[16])
{
	if (hash == NULL) return;

	DEBUG(5,("make_arc4_owf: %d\n", __LINE__));
	
	if (data != NULL)
	{
		memcpy(hash->data, data, sizeof(hash->data));
	}
	else
	{
		bzero(hash->data, sizeof(hash->data));
	}
}

/*******************************************************************
reads or writes an ARC4_OWF structure.
********************************************************************/
char* smb_io_arc4_owf(BOOL io, ARC4_OWF *hash, char *q, char *base, int align, int depth)
{
	if (hash == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_arc4_owf\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_PCVAL("data", depth, base, io, q, hash->data, 16); q += 16;

	return q;
}

/*******************************************************************
makes a DOM_ID_INFO_1 structure.
********************************************************************/
void make_id_info1(DOM_ID_INFO_1 *id, char *domain_name,
				uint32 param_ctrl, uint32 log_id_low, uint32 log_id_high,
				char *user_name, char *wksta_name,
				char arc4_lm_owf[16], char arc4_nt_owf[16])
{
	int len_domain_name = strlen(domain_name);
	int len_user_name   = strlen(user_name  );
	int len_wksta_name  = strlen(wksta_name );

	if (id == NULL) return;

	DEBUG(5,("make_id_info1: %d\n", __LINE__));

	id->ptr_id_info1 = 1;

	make_uni_hdr(&(id->hdr_domain_name), len_domain_name, len_domain_name, 4);

	id->param_ctrl = param_ctrl;
	make_logon_id(&(id->logon_id), log_id_low, log_id_high);

	make_uni_hdr(&(id->hdr_user_name  ), len_user_name  , len_user_name  , 4);
	make_uni_hdr(&(id->hdr_wksta_name ), len_wksta_name , len_wksta_name , 4);

	make_arc4_owf(&(id->arc4_lm_owf), arc4_lm_owf);
	make_arc4_owf(&(id->arc4_nt_owf), arc4_nt_owf);

	make_unistr2(&(id->uni_domain_name), domain_name, len_domain_name);
	make_unistr2(&(id->uni_user_name  ), user_name  , len_user_name  );
	make_unistr2(&(id->uni_wksta_name ), wksta_name , len_wksta_name );
}

/*******************************************************************
reads or writes an DOM_ID_INFO_1 structure.
********************************************************************/
char* smb_io_id_info1(BOOL io, DOM_ID_INFO_1 *id, char *q, char *base, int align, int depth)
{
	if (id == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_id_info1\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("ptr_id_info1", depth, base, io, q, id->ptr_id_info1); q += 4;

	if (id->ptr_id_info1 != 0)
	{
		q = smb_io_unihdr(io, &(id->hdr_domain_name), q, base, align, depth);

		DBG_RW_IVAL("param_ctrl", depth, base, io, q, id->param_ctrl); q += 4;
		q = smb_io_logon_id(io, &(id->logon_id), q, base, align, depth);

		q = smb_io_unihdr(io, &(id->hdr_user_name  ), q, base, align, depth);
		q = smb_io_unihdr(io, &(id->hdr_wksta_name ), q, base, align, depth);

		q = smb_io_arc4_owf(io, &(id->arc4_lm_owf), q, base, align, depth);
		q = smb_io_arc4_owf(io, &(id->arc4_nt_owf), q, base, align, depth);

		q = smb_io_unistr2(io, &(id->uni_domain_name), q, base, align, depth);
		q = smb_io_unistr2(io, &(id->uni_user_name  ), q, base, align, depth);
		q = smb_io_unistr2(io, &(id->uni_wksta_name ), q, base, align, depth);
	}

	return q;
}

/*******************************************************************
makes a DOM_SAM_INFO structure.
********************************************************************/
void make_sam_info(DOM_SAM_INFO *sam,
				char *logon_srv, char *comp_name, DOM_CRED *clnt_cred,
				DOM_CRED *rtn_cred, uint16 logon_level, uint16 switch_value,
				DOM_ID_INFO_1 *id1)
{
	if (sam == NULL) return;

	DEBUG(5,("make_sam_info: %d\n", __LINE__));

	make_clnt_info2(&(sam->client), logon_srv, comp_name, clnt_cred);

	if (rtn_cred != NULL)
	{
		sam->ptr_rtn_cred = 1;
		memcpy(&(sam->rtn_cred), rtn_cred, sizeof(sam->rtn_cred));
	}
	else
	{
		sam->ptr_rtn_cred = 0;
	}

	sam->logon_level  = logon_level;
	sam->switch_value = switch_value;

	switch (sam->switch_value)
	{
		case 1:
		{
			sam->auth.id1 = id1;
			break;
		}
		default:
		{
			/* PANIC! */
			DEBUG(4,("make_sam_info: unknown switch_value!\n"));
			break;
		}
	}
}

/*******************************************************************
reads or writes a DOM_SAM_INFO structure.
********************************************************************/
char* smb_io_sam_info(BOOL io, DOM_SAM_INFO *sam, char *q, char *base, int align, int depth)
{
	if (sam == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_sam_info\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	q = smb_io_clnt_info2(io, &(sam->client  ), q, base, align, depth);

	DBG_RW_IVAL("ptr_rtn_cred", depth, base, io, q, sam->ptr_rtn_cred); q += 4;
	q = smb_io_cred      (io, &(sam->rtn_cred), q, base, align, depth);

	DBG_RW_SVAL("logon_level ", depth, base, io, q, sam->logon_level); q += 2;
	DBG_RW_SVAL("switch_value", depth, base, io, q, sam->switch_value); q += 2;

	switch (sam->switch_value)
	{
		case 1:
		{
			q = smb_io_id_info1(io, sam->auth.id1, q, base, align, depth);
			break;
		}
		default:
		{
			/* PANIC! */
			DEBUG(4,("smb_io_sam_info: unknown switch_value!\n"));
			break;
		}
	}
	return q;
}

/*******************************************************************
reads or writes a DOM_GID structure.
********************************************************************/
char* smb_io_gid(BOOL io, DOM_GID *gid, char *q, char *base, int align, int depth)
{
	if (gid == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_gid\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("g_rid", depth, base, io, q, gid->g_rid); q += 4;
	DBG_RW_IVAL("attr ", depth, base, io, q, gid->attr ); q += 4;

	return q;
}

/*******************************************************************
creates an RPC_HDR structure.
********************************************************************/
void make_rpc_header(RPC_HDR *hdr, enum RPC_PKT_TYPE pkt_type,
				uint32 call_id, int data_len, uint8 opnum)
{
	if (hdr == NULL) return;

	hdr->major        = 5;               /* RPC version 5 */
	hdr->minor        = 0;               /* minor version 0 */
	hdr->pkt_type     = pkt_type;        /* RPC packet type */
	hdr->frag         = 3;               /* first frag + last frag */
	hdr->pack_type    = 0x10;            /* packed data representation */
	hdr->frag_len     = data_len;        /* fragment length, fill in later */
	hdr->auth_len     = 0;               /* authentication length */
	hdr->call_id      = call_id;         /* call identifier - match incoming RPC */
	hdr->alloc_hint   = data_len - 0x18; /* allocation hint (no idea) */
	hdr->context_id   = 0;               /* presentation context identifier */
	hdr->cancel_count = 0;               /* cancel count */
	hdr->opnum        = opnum;           /* opnum */
}

/*******************************************************************
reads or writes an RPC_HDR structure.
********************************************************************/
char* smb_io_rpc_hdr(BOOL io, RPC_HDR *rpc, char *q, char *base, int align, int depth)
{
	if (rpc == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_rpc_hdr\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	DBG_RW_CVAL("major     ", depth, base, io, q, rpc->major); q++;
	DBG_RW_CVAL("minor     ", depth, base, io, q, rpc->minor); q++;
	DBG_RW_CVAL("pkt_type  ", depth, base, io, q, rpc->pkt_type); q++;
	DBG_RW_CVAL("frag      ", depth, base, io, q, rpc->frag); q++;
	DBG_RW_IVAL("pack_type ", depth, base, io, q, rpc->pack_type); q += 4;
	DBG_RW_SVAL("frag_len  ", depth, base, io, q, rpc->frag_len); q += 2;
	DBG_RW_SVAL("auth_len  ", depth, base, io, q, rpc->auth_len); q += 2;
	DBG_RW_IVAL("call_id   ", depth, base, io, q, rpc->call_id); q += 4;
	DBG_RW_IVAL("alloc_hint", depth, base, io, q, rpc->alloc_hint); q += 4;
	DBG_RW_CVAL("context_id", depth, base, io, q, rpc->context_id); q++;
	DBG_RW_CVAL("cancel_ct ", depth, base, io, q, rpc->cancel_count); q++;
	DBG_RW_CVAL("opnum     ", depth, base, io, q, rpc->opnum); q++;

	return q;
}

/*******************************************************************
makes an LSA_OBJ_ATTR structure.
********************************************************************/
void make_obj_attr(LSA_OBJ_ATTR *attr, uint32 attributes, uint32 sec_qos)
{
	if (attr == NULL) return;

	DEBUG(5,("make_obj_attr\n"));

	attr->len = 0x18; /* length of object attribute block, in bytes */
	attr->ptr_root_dir = 0;
	attr->ptr_obj_name = 0;
	attr->attributes = attributes;
	attr->ptr_sec_desc = 0;
	attr->sec_qos = sec_qos;
}

/*******************************************************************
reads or writes an LSA_OBJ_ATTR structure.
********************************************************************/
char* smb_io_obj_attr(BOOL io, LSA_OBJ_ATTR *attr, char *q, char *base, int align, int depth)
{
	char *start;

	if (attr == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_obj_attr\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	start = q;

	/* these pointers had _better_ be zero, because we don't know
	   what they point to!
	 */
	DBG_RW_IVAL("len"         , depth, base, io, q, attr->len         ); q += 4; /* 0x18 - length (in bytes) inc. the length field. */
	DBG_RW_IVAL("ptr_root_dir", depth, base, io, q, attr->ptr_root_dir); q += 4; /* 0 - root directory (pointer) */
	DBG_RW_IVAL("ptr_obj_name", depth, base, io, q, attr->ptr_obj_name); q += 4; /* 0 - object name (pointer) */
	DBG_RW_IVAL("attributes"  , depth, base, io, q, attr->attributes  ); q += 4; /* 0 - attributes (undocumented) */
	DBG_RW_IVAL("ptr_sec_desc", depth, base, io, q, attr->ptr_sec_desc); q += 4; /* 0 - security descriptior (pointer) */
	DBG_RW_IVAL("sec_qos"     , depth, base, io, q, attr->sec_qos     ); q += 4; /* 0 - security quality of service */

	if (attr->len != PTR_DIFF(q, start))
	{
		DEBUG(3,("smb_io_obj_attr: length %lx does not match size %lx\n",
		         attr->len, PTR_DIFF(q, start)));
	}

	return q;
}

/*******************************************************************
reads or writes an LSA_POL_HND structure.
********************************************************************/
char* smb_io_pol_hnd(BOOL io, LSA_POL_HND *pol, char *q, char *base, int align, int depth)
{
	if (pol == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_pol_hnd\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_PCVAL("data", depth, base, io, q, pol->data, POL_HND_SIZE); q += POL_HND_SIZE;

	return q;
}

/*******************************************************************
reads or writes a dom query structure.
********************************************************************/
char* smb_io_dom_query_3(BOOL io, DOM_QUERY_3 *d_q, char *q, char *base, int align, int depth)
{
	return smb_io_dom_query(io, d_q, q, base, align, depth);
}

/*******************************************************************
reads or writes a dom query structure.
********************************************************************/
char* smb_io_dom_query_5(BOOL io, DOM_QUERY_3 *d_q, char *q, char *base, int align, int depth)
{
	return smb_io_dom_query(io, d_q, q, base, align, depth);
}

/*******************************************************************
reads or writes a dom query structure.
********************************************************************/
char* smb_io_dom_query(BOOL io, DOM_QUERY *d_q, char *q, char *base, int align, int depth)
{
	if (d_q == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_dom_query\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_SVAL("uni_dom_max_len", depth, base, io, q, d_q->uni_dom_max_len); q += 2; /* domain name string length * 2 */
	DBG_RW_SVAL("uni_dom_str_len", depth, base, io, q, d_q->uni_dom_str_len); q += 2; /* domain name string length * 2 */

	DBG_RW_IVAL("buffer_dom_name", depth, base, io, q, d_q->buffer_dom_name); q += 4; /* undocumented domain name string buffer pointer */
	DBG_RW_IVAL("buffer_dom_sid ", depth, base, io, q, d_q->buffer_dom_sid ); q += 4; /* undocumented domain SID string buffer pointer */

	if (d_q->buffer_dom_name != 0)
	{
		q = smb_io_unistr2(io, &(d_q->uni_domain_name), q, base, align, depth); /* domain name (unicode string) */
	}
	if (d_q->buffer_dom_sid != 0)
	{
		q = smb_io_dom_sid(io, &(d_q->dom_sid), q, base, align, depth); /* domain SID */
	}

	return q;
}

/*******************************************************************
reads or writes a DOM_R_REF structure.
********************************************************************/
char* smb_io_dom_r_ref(BOOL io, DOM_R_REF *r_r, char *q, char *base, int align, int depth)
{
	int i;

	DEBUG(5,("%s%04x smb_io_dom_r_ref\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	if (r_r == NULL) return NULL;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("undoc_buffer   ", depth, base, io, q, r_r->undoc_buffer); q += 4; /* undocumented buffer pointer. */
	DBG_RW_IVAL("num_ref_doms_1 ", depth, base, io, q, r_r->num_ref_doms_1); q += 4; /* num referenced domains? */
	DBG_RW_IVAL("buffer_dom_name", depth, base, io, q, r_r->buffer_dom_name); q += 4; /* undocumented domain name buffer pointer. */
	DBG_RW_IVAL("max_entries    ", depth, base, io, q, r_r->max_entries); q += 4; /* 32 - max number of entries */
	DBG_RW_IVAL("num_ref_doms_2 ", depth, base, io, q, r_r->num_ref_doms_2); q += 4; /* 4 - num referenced domains? */

	q = smb_io_unihdr2(io, &(r_r->hdr_dom_name), q, base, align, depth); /* domain name unicode string header */

	for (i = 0; i < r_r->num_ref_doms_1-1; i++)
	{
		q = smb_io_unihdr2(io, &(r_r->hdr_ref_dom[i]), q, base, align, depth);
	}

	q = smb_io_unistr(io, &(r_r->uni_dom_name), q, base, align, depth); /* domain name unicode string */

	for (i = 0; i < r_r->num_ref_doms_2; i++)
	{
		q = smb_io_dom_sid(io, &(r_r->ref_dom[i]), q, base, align, depth); /* referenced domain SIDs */
	}
	return q;
}

/*******************************************************************
reads or writes a DOM_NAME structure.
********************************************************************/
char* smb_io_dom_name(BOOL io, DOM_NAME *name, char *q, char *base, int align, int depth)
{
	if (name == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_dom_name\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("uni_str_len", depth, base, io, q, name->uni_str_len); q += 4;

	/* don't know if len is specified by uni_str_len member... */
	/* assume unicode string is unicode-null-terminated, instead */

	q = smb_io_unistr(io, &(name->str), q, base, align, depth);

	return q;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* smb_io_neg_flags(BOOL io, NEG_FLAGS *neg, char *q, char *base, int align, int depth)
{
	if (neg == NULL) return NULL;

	DEBUG(5,("%s%04x smb_io_neg_flags\n",  tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("neg_flags", depth, base, io, q, neg->neg_flags); q += 4;

	return q;
}


#if 0
/*******************************************************************
reads or writes a structure.
********************************************************************/
 char* smb_io_(BOOL io, *, char *q, char *base, int align, int depth)
{
	if (== NULL) return NULL;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("", depth, base, io, q, ); q += 4;

	return q;
}
#endif

