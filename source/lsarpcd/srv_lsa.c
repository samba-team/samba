
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison                    1998.
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
#include "nterr.h"

extern int DEBUGLEVEL;
extern DOM_SID global_sam_sid;

/***************************************************************************
lsa_reply_open_policy2
 ***************************************************************************/
static void lsa_reply_open_policy2(prs_struct *rdata)
{
	int i;
	LSA_R_OPEN_POL2 r_o;

	ZERO_STRUCT(r_o);

	/* set up the LSA QUERY INFO response */

	for (i = 4; i < POL_HND_SIZE; i++)
	{
		r_o.pol.data[i] = i;
	}
	r_o.status = 0x0;

	/* store the response in the SMB stream */
	lsa_io_r_open_pol2("", &r_o, rdata, 0);
}

/***************************************************************************
lsa_reply_open_policy
 ***************************************************************************/
static void lsa_reply_open_policy(prs_struct *rdata)
{
	int i;
	LSA_R_OPEN_POL r_o;

	ZERO_STRUCT(r_o);

	/* set up the LSA QUERY INFO response */

	for (i = 4; i < POL_HND_SIZE; i++)
	{
		r_o.pol.data[i] = i;
	}
	r_o.status = 0x0;

	/* store the response in the SMB stream */
	lsa_io_r_open_pol("", &r_o, rdata, 0);
}

/***************************************************************************
lsa_reply_query_info
 ***************************************************************************/
static void lsa_reply_enum_trust_dom(LSA_Q_ENUM_TRUST_DOM *q_e,
				prs_struct *rdata,
				uint32 enum_context, char *dom_name, DOM_SID *dom_sid)
{
	LSA_R_ENUM_TRUST_DOM r_e;

	ZERO_STRUCT(r_e);

	/* set up the LSA QUERY INFO response */
	make_r_enum_trust_dom(&r_e, enum_context, dom_name, dom_sid,
	      dom_name != NULL ? 0x0 : 0x80000000 | NT_STATUS_UNABLE_TO_FREE_VM);

	/* store the response in the SMB stream */
	lsa_io_r_enum_trust_dom("", &r_e, rdata, 0);
}

/***************************************************************************
make_dom_query
 ***************************************************************************/
static void make_dom_query(DOM_QUERY *d_q, char *dom_name, DOM_SID *dom_sid)
{
	int domlen = strlen(dom_name);

	d_q->uni_dom_max_len = domlen * 2;
	d_q->uni_dom_str_len = domlen * 2;

	d_q->buffer_dom_name = 4; /* domain buffer pointer */
	d_q->buffer_dom_sid  = 2; /* domain sid pointer */

	/* this string is supposed to be character short */
	make_unistr2(&(d_q->uni_domain_name), dom_name, domlen);

	make_dom_sid2(&(d_q->dom_sid), dom_sid);
}
/***************************************************************************
lsa_reply_query_info
 ***************************************************************************/
static void lsa_reply_query_info(LSA_Q_QUERY_INFO *q_q, prs_struct *rdata,
				char *dom_name, DOM_SID *dom_sid)
{
	LSA_R_QUERY_INFO r_q;

	ZERO_STRUCT(r_q);

	/* set up the LSA QUERY INFO response */

	r_q.undoc_buffer = 0x22000000; /* bizarre */
	r_q.info_class = q_q->info_class;

	make_dom_query(&r_q.dom.id5, dom_name, dom_sid);

	r_q.status = 0x0;

	/* store the response in the SMB stream */
	lsa_io_r_query("", &r_q, rdata, 0);
}


/***************************************************************************
api_lsa_open_policy
 ***************************************************************************/
static void api_lsa_open_policy2( uint16 vuid, prs_struct *data,
                             prs_struct *rdata )
{
	LSA_Q_OPEN_POL2 q_o;

	ZERO_STRUCT(q_o);

	/* grab the server, object attributes and desired access flag...*/
	lsa_io_q_open_pol2("", &q_o, data, 0);

	/* lkclXXXX having decoded it, ignore all fields in the open policy! */

	/* return a 20 byte policy handle */
	lsa_reply_open_policy2(rdata);
}

/***************************************************************************
api_lsa_open_policy
 ***************************************************************************/
static void api_lsa_open_policy( uint16 vuid, prs_struct *data,
                             prs_struct *rdata )
{
	LSA_Q_OPEN_POL q_o;

	ZERO_STRUCT(q_o);

	/* grab the server, object attributes and desired access flag...*/
	lsa_io_q_open_pol("", &q_o, data, 0);

	/* lkclXXXX having decoded it, ignore all fields in the open policy! */

	/* return a 20 byte policy handle */
	lsa_reply_open_policy(rdata);
}

/***************************************************************************
api_lsa_enum_trust_dom
 ***************************************************************************/
static void api_lsa_enum_trust_dom( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	LSA_Q_ENUM_TRUST_DOM q_e;

	ZERO_STRUCT(q_e);

	/* grab the enum trust domain context etc. */
	lsa_io_q_enum_trust_dom("", &q_e, data, 0);

	/* construct reply.  return status is always 0x0 */
	lsa_reply_enum_trust_dom(&q_e, rdata, 0, NULL, NULL);
}

/***************************************************************************
api_lsa_query_info
 ***************************************************************************/
static void api_lsa_query_info( uint16 vuid, prs_struct *data,
                                prs_struct *rdata )
{
	LSA_Q_QUERY_INFO q_i;
	pstring dom_name;

	ZERO_STRUCT(q_i);

	/* grab the info class and policy handle */
	lsa_io_q_query("", &q_i, data, 0);

	pstrcpy(dom_name, lp_workgroup());

	/* construct reply.  return status is always 0x0 */
	lsa_reply_query_info(&q_i, rdata, dom_name, &global_sam_sid);
}

/***************************************************************************
 api_lsa_close
 ***************************************************************************/
static void api_lsa_close( uint16 vuid, prs_struct *data,
                                  prs_struct *rdata)
{
	/* XXXX this is NOT good */
	char *q = mem_data(&(rdata->data), rdata->offset);

	SIVAL(q, 0, 0);
	q += 4;
	SIVAL(q, 0, 0);
	q += 4;
	SIVAL(q, 0, 0);
	q += 4;
	SIVAL(q, 0, 0);
	q += 4;
	SIVAL(q, 0, 0); 
	q += 4;
	SIVAL(q, 0, 0);
	q += 4;

	rdata->offset += 24;
}

/***************************************************************************
 api_lsa_open_secret
 ***************************************************************************/
static void api_lsa_open_secret( uint16 vuid, prs_struct *data,
                                  prs_struct *rdata)
{
	/* XXXX this is NOT good */
	char *q = mem_data(&(rdata->data), rdata->offset);

	SIVAL(q, 0, 0);
	q += 4;
	SIVAL(q, 0, 0);
	q += 4;
	SIVAL(q, 0, 0);
	q += 4;
	SIVAL(q, 0, 0);
	q += 4;
	SIVAL(q, 0, 0);
	q += 4;
	SIVAL(q, 0, 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND);
	q += 4;
	
	rdata->offset += 24;
}

/***************************************************************************
 \PIPE\ntlsa commands
 ***************************************************************************/
static struct api_struct api_lsa_cmds[] =
{
	{ "LSA_OPENPOLICY2"     , LSA_OPENPOLICY2     , api_lsa_open_policy2   },
	{ "LSA_OPENPOLICY"      , LSA_OPENPOLICY      , api_lsa_open_policy    },
	{ "LSA_QUERYINFOPOLICY" , LSA_QUERYINFOPOLICY , api_lsa_query_info     },
	{ "LSA_ENUMTRUSTDOM"    , LSA_ENUMTRUSTDOM    , api_lsa_enum_trust_dom },
	{ "LSA_CLOSE"           , LSA_CLOSE           , api_lsa_close          },
	{ "LSA_OPENSECRET"      , LSA_OPENSECRET      , api_lsa_open_secret    },
	{ NULL                  , 0                   , NULL                   }
};

/***************************************************************************
 api_ntLsarpcTNP
 ***************************************************************************/
BOOL api_ntlsa_rpc(pipes_struct *p, prs_struct *data)
{
	return api_rpcTNP(p, "api_ntlsa_rpc", api_lsa_cmds, data);
}
