/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Pipe SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1997,
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997.
   Copyright (C) Paul Ashton  1997.
   
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
/*
   This file handles reply_ calls on named pipes that the server
   makes to handle specific protocols
*/


#include "includes.h"
#include "trans2.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#ifdef NTDOMAIN

static int lsa_reply_open_policy(char *q, char *base)
{
	int i;
	LSA_R_OPEN_POL r_o;

	/* set up the LSA QUERY INFO response */
	/* bzero(&(r_o.pol.data), POL_HND_SIZE); */
	for (i = 0; i < POL_HND_SIZE; i++)
	{
		r_o.pol.data[i] = i;
	}
	r_o.status = 0x0;

	/* store the response in the SMB stream */
	q = lsa_io_r_open_pol(False, &r_o, q, base, 4, 0);

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

static void make_dom_query(DOM_QUERY *d_q, char *dom_name, char *dom_sid)
{
	int domlen = strlen(dom_name);

	d_q->uni_dom_max_len = domlen * 2;
	d_q->uni_dom_str_len = domlen * 2;

	d_q->buffer_dom_name = 4; /* domain buffer pointer */
	d_q->buffer_dom_sid  = 2; /* domain sid pointer */

	/* this string is supposed to be character short */
	make_unistr2(&(d_q->uni_domain_name), dom_name, domlen);

	make_dom_sid(&(d_q->dom_sid), dom_sid);
}

static int lsa_reply_query_info(LSA_Q_QUERY_INFO *q_q, char *q, char *base,
				char *dom_name, char *dom_sid)
{
	LSA_R_QUERY_INFO r_q;

	/* set up the LSA QUERY INFO response */

	r_q.undoc_buffer = 0x22000000; /* bizarre */
	r_q.info_class = q_q->info_class;

	make_dom_query(&r_q.dom.id5, dom_name, dom_sid);

	r_q.status = 0x0;

	/* store the response in the SMB stream */
	q = lsa_io_r_query(False, &r_q, q, base, 4, 0);

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/* pretty much hard-coded choice of "other" sids, unfortunately... */
static void make_dom_ref(DOM_R_REF *ref,
				char *dom_name, char *dom_sid,
				char *other_sid1, char *other_sid2, char *other_sid3)
{
	int len_dom_name   = strlen(dom_name);
	int len_other_sid1 = strlen(other_sid1);
	int len_other_sid2 = strlen(other_sid2);
	int len_other_sid3 = strlen(other_sid3);

	ref->undoc_buffer = 1;
	ref->num_ref_doms_1 = 4;
	ref->buffer_dom_name = 1;
	ref->max_entries = 32;
	ref->num_ref_doms_2 = 4;

	make_uni_hdr2(&(ref->hdr_dom_name  ), len_dom_name  , len_dom_name  , 0);
	make_uni_hdr2(&(ref->hdr_ref_dom[0]), len_other_sid1, len_other_sid1, 0);
	make_uni_hdr2(&(ref->hdr_ref_dom[1]), len_other_sid2, len_other_sid2, 0);
	make_uni_hdr2(&(ref->hdr_ref_dom[2]), len_other_sid3, len_other_sid3, 0);

	if (dom_name != NULL)
	{
		make_unistr(&(ref->uni_dom_name), dom_name);
	}

	make_dom_sid(&(ref->ref_dom[0]), dom_sid   );
	make_dom_sid(&(ref->ref_dom[1]), other_sid1);
	make_dom_sid(&(ref->ref_dom[2]), other_sid2);
	make_dom_sid(&(ref->ref_dom[3]), other_sid3);
}

static void make_reply_lookup_rids(LSA_R_LOOKUP_RIDS *r_l,
				int num_entries, uint32 dom_rids[MAX_LOOKUP_SIDS],
				char *dom_name, char *dom_sid,
				char *other_sid1, char *other_sid2, char *other_sid3)
{
	int i;

	make_dom_ref(&(r_l->dom_ref), dom_name, dom_sid,
	             other_sid1, other_sid2, other_sid3);

	r_l->num_entries = num_entries;
	r_l->undoc_buffer = 1;
	r_l->num_entries2 = num_entries;

	for (i = 0; i < num_entries; i++)
	{
		make_dom_rid2(&(r_l->dom_rid[i]), dom_rids[i]);
	}

	r_l->num_entries3 = num_entries;
}

static void make_reply_lookup_sids(LSA_R_LOOKUP_SIDS *r_l,
				int num_entries, fstring dom_sids[MAX_LOOKUP_SIDS],
				char *dom_name, char *dom_sid,
				char *other_sid1, char *other_sid2, char *other_sid3)
{
	int i;

	make_dom_ref(&(r_l->dom_ref), dom_name, dom_sid,
	             other_sid1, other_sid2, other_sid3);

	r_l->num_entries = num_entries;
	r_l->undoc_buffer = 1;
	r_l->num_entries2 = num_entries;

	for (i = 0; i < num_entries; i++)
	{
		make_dom_sid2(&(r_l->dom_sid[i]), dom_sids[i]);
	}

	r_l->num_entries3 = num_entries;
}

static int lsa_reply_lookup_sids(char *q, char *base,
				int num_entries, fstring dom_sids[MAX_LOOKUP_SIDS],
				char *dom_name, char *dom_sid,
				char *other_sid1, char *other_sid2, char *other_sid3)
{
	LSA_R_LOOKUP_SIDS r_l;

	/* set up the LSA Lookup SIDs response */
	make_reply_lookup_sids(&r_l, num_entries, dom_sids,
				dom_name, dom_sid, other_sid1, other_sid2, other_sid3);
	r_l.status = 0x0;

	/* store the response in the SMB stream */
	q = lsa_io_r_lookup_sids(False, &r_l, q, base, 4, 0);

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

static int lsa_reply_lookup_rids(char *q, char *base,
				int num_entries, uint32 dom_rids[MAX_LOOKUP_SIDS],
				char *dom_name, char *dom_sid,
				char *other_sid1, char *other_sid2, char *other_sid3)
{
	LSA_R_LOOKUP_RIDS r_l;

	/* set up the LSA Lookup RIDs response */
	make_reply_lookup_rids(&r_l, num_entries, dom_rids,
				dom_name, dom_sid, other_sid1, other_sid2, other_sid3);
	r_l.status = 0x0;

	/* store the response in the SMB stream */
	q = lsa_io_r_lookup_rids(False, &r_l, q, base, 4, 0);

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

static void api_lsa_open_policy( char *param, char *data,
                             char **rdata, int *rdata_len )
{
	/* we might actually want to decode the query, but it's not necessary */
	/* lsa_io_q_open_policy(...); */

	/* return a 20 byte policy handle */
	*rdata_len = lsa_reply_open_policy(*rdata + 0x18, *rdata);
}

static void api_lsa_query_info( char *param, char *data,
                                char **rdata, int *rdata_len )
{
	LSA_Q_QUERY_INFO q_i;
	pstring dom_name;
	pstring dom_sid;

	/* grab the info class and policy handle */
	lsa_io_q_query(True, &q_i, data + 0x18, data, 4, 0);

	pstrcpy(dom_name, lp_workgroup());
	pstrcpy(dom_sid , lp_domainsid());

	/* construct reply.  return status is always 0x0 */
	*rdata_len = lsa_reply_query_info(&q_i, *rdata + 0x18, *rdata, 
									 dom_name, dom_sid);
}

static void api_lsa_lookup_sids( char *param, char *data,
                                 char **rdata, int *rdata_len )
{
	int i;
	LSA_Q_LOOKUP_SIDS q_l;
	pstring dom_name;
	pstring dom_sid;
	fstring dom_sids[MAX_LOOKUP_SIDS];

	/* grab the info class and policy handle */
	lsa_io_q_lookup_sids(True, &q_l, data + 0x18, data, 4, 0);

	pstrcpy(dom_name, lp_workgroup());
	pstrcpy(dom_sid , lp_domainsid());

	/* convert received SIDs to strings, so we can do them. */
	for (i = 0; i < q_l.num_entries; i++)
	{
		fstrcpy(dom_sids[i], dom_sid_to_string(&(q_l.dom_sids[i])));
	}

	/* construct reply.  return status is always 0x0 */
	*rdata_len = lsa_reply_lookup_sids(*rdata + 0x18, *rdata,
	            q_l.num_entries, dom_sids, /* text-converted SIDs */
				dom_name, dom_sid, /* domain name, domain SID */
				"S-1-1", "S-1-3", "S-1-5"); /* the three other SIDs */
}

static void api_lsa_lookup_names( char *param, char *data,
                                  char **rdata, int *rdata_len )
{
	int i;
	LSA_Q_LOOKUP_RIDS q_l;
	pstring dom_name;
	pstring dom_sid;
	uint32 dom_rids[MAX_LOOKUP_SIDS];

	/* grab the info class and policy handle */
	lsa_io_q_lookup_rids(True, &q_l, data + 0x18, data, 4, 0);

	pstrcpy(dom_name, lp_workgroup());
	pstrcpy(dom_sid , lp_domainsid());

	/* convert received RIDs to strings, so we can do them. */
	for (i = 0; i < q_l.num_entries; i++)
	{
		char *user_name = unistr2(q_l.lookup_name[i].str.buffer);
		dom_rids[i] = name_to_rid(user_name);
	}

	/* construct reply.  return status is always 0x0 */
	*rdata_len = lsa_reply_lookup_rids(*rdata + 0x18, *rdata,
	            q_l.num_entries, dom_rids, /* text-converted SIDs */
				dom_name, dom_sid, /* domain name, domain SID */
				"S-1-1", "S-1-3", "S-1-5"); /* the three other SIDs */
}

BOOL api_ntLsarpcTNP(int cnum,int uid, char *param,char *data,
		     int mdrcnt,int mprcnt,
		     char **rdata,char **rparam,
		     int *rdata_len,int *rparam_len)
{
	uint16 opnum = SVAL(data,22);

	int pkttype = CVAL(data, 2);
	if (pkttype == 0x0b) /* RPC BIND */
	{
		DEBUG(4,("netlogon rpc bind %x\n",pkttype));
		LsarpcTNP1(data,rdata,rdata_len);
		return True;
	}

	DEBUG(4,("ntlsa TransactNamedPipe op %x\n",opnum));
	switch (opnum)
	{
		case LSA_OPENPOLICY:
		{
			DEBUG(3,("LSA_OPENPOLICY\n"));
			api_lsa_open_policy(param, data, rdata, rdata_len);
			make_rpc_reply(data, *rdata, *rdata_len);
			break;
		}

		case LSA_QUERYINFOPOLICY:
		{
			DEBUG(3,("LSA_QUERYINFOPOLICY\n"));

			api_lsa_query_info(param, data, rdata, rdata_len);
			make_rpc_reply(data, *rdata, *rdata_len);
			break;
		}

		case LSA_ENUMTRUSTDOM:
		{
			char *q = *rdata + 0x18;

			DEBUG(3,("LSA_ENUMTRUSTDOM\n"));

			initrpcreply(data, *rdata);

			SIVAL(q, 0, 0); /* enumeration context */
			SIVAL(q, 0, 4); /* entries read */
			SIVAL(q, 0, 8); /* trust information */

			endrpcreply(data, *rdata, q-*rdata, 0x8000001a, rdata_len);

			break;
		}

		case LSA_CLOSE:
		{
			char *q = *rdata + 0x18;

			DEBUG(3,("LSA_CLOSE\n"));

			initrpcreply(data, *rdata);

			SIVAL(q, 0, 0);
			SIVAL(q, 0, 4);
			SIVAL(q, 0, 8);
			SIVAL(q, 0, 12);
			SIVAL(q, 0, 16);

			endrpcreply(data, *rdata, q-*rdata, 0, rdata_len);

			break;
		}

		case LSA_OPENSECRET:
		{
			char *q = *rdata + 0x18;
			DEBUG(3,("LSA_OPENSECRET\n"));

			initrpcreply(data, *rdata);

			SIVAL(q, 0, 0);
			SIVAL(q, 0, 4);
			SIVAL(q, 0, 8);
			SIVAL(q, 0, 12);
			SIVAL(q, 0, 16);

			endrpcreply(data, *rdata, q-*rdata, 0xc000034, rdata_len);

			break;
		}

		case LSA_LOOKUPSIDS:
		{
			DEBUG(3,("LSA_OPENSECRET\n"));
			api_lsa_lookup_sids(param, data, rdata, rdata_len);
			make_rpc_reply(data, *rdata, *rdata_len);
			break;
		}

		case LSA_LOOKUPNAMES:
		{
			DEBUG(3,("LSA_LOOKUPNAMES\n"));
			api_lsa_lookup_names(param, data, rdata, rdata_len);
			make_rpc_reply(data, *rdata, *rdata_len);
			break;
		}

		default:
		{
			DEBUG(4, ("NTLSARPC, unknown code: %lx\n", opnum));
			break;
		}
	}
	return True;
}

#endif /* NTDOMAIN */
