
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
extern DOM_SID global_machine_sid;

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
make_dom_ref

 pretty much hard-coded choice of "other" sids, unfortunately...

 ***************************************************************************/
static void make_dom_ref(DOM_R_REF *ref, char *dom_name, DOM_SID *dom_sid,
                         DOM_SID *other_sid1, DOM_SID *other_sid2, DOM_SID *other_sid3)
{
	int len_dom_name   = strlen(dom_name);

	ref->undoc_buffer = 1;
	ref->num_ref_doms_1 = 4;
	ref->buffer_dom_name = 1;
	ref->max_entries = 32;
	ref->num_ref_doms_2 = 4;

	make_uni_hdr2(&(ref->hdr_dom_name  ), len_dom_name  , len_dom_name  , 0);
	make_uni_hdr2(&(ref->hdr_ref_dom[0]), sizeof(DOM_SID), sizeof(DOM_SID), 0);
	make_uni_hdr2(&(ref->hdr_ref_dom[1]), sizeof(DOM_SID), sizeof(DOM_SID), 0);
	make_uni_hdr2(&(ref->hdr_ref_dom[2]), sizeof(DOM_SID), sizeof(DOM_SID), 0);

	if (dom_name != NULL)
	{
		make_unistr(&(ref->uni_dom_name), dom_name);
	}

	make_dom_sid2(&(ref->ref_dom[0]), dom_sid   );
	make_dom_sid2(&(ref->ref_dom[1]), other_sid1);
	make_dom_sid2(&(ref->ref_dom[2]), other_sid2);
	make_dom_sid2(&(ref->ref_dom[3]), other_sid3);
}

/***************************************************************************
make_reply_lookup_rids
 ***************************************************************************/
static void make_reply_lookup_rids(LSA_R_LOOKUP_RIDS *r_l,
				int num_entries, uint32 dom_rids[MAX_LOOKUP_SIDS],
				char *dom_name, DOM_SID *dom_sid,
				DOM_SID *other_sid1, DOM_SID *other_sid2, DOM_SID *other_sid3)
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

/***************************************************************************
make_lsa_trans_names
 ***************************************************************************/
static void make_lsa_trans_names(LSA_TRANS_NAME_ENUM *trn,
				int num_entries, DOM_SID2 sid[MAX_LOOKUP_SIDS],
				uint32 *total)
{
	uint32 status = 0x0;
	int i;
	(*total) = 0;

	for (i = 0; i < num_entries; i++)
	{
		uint32 rid = 0xffffffff;
		uint8 num_auths = sid[i].sid.num_auths;
		fstring name;
		uint32 type;
		
		trn->ptr_name[i] = 0;
		trn->ptr_name[(*total)] = 0;

		/* find the rid to look up */
		if (num_auths != 0)
		{
			rid = sid[i].sid.sub_auths[num_auths-1];

			status = 0xC0000000 | NT_STATUS_NONE_MAPPED;

			status = (status != 0x0) ? lookup_user_name (rid, name, &type) : status;
			status = (status != 0x0) ? lookup_group_name(rid, name, &type) : status;
			status = (status != 0x0) ? lookup_alias_name(rid, name, &type) : status;
		}

		if (status == 0x0)
		{
			trn->ptr_name[i] = 1;
			make_lsa_trans_name(&(trn->name[(*total)]), type, name, (*total));
			(*total)++;
		}
	}

	trn->num_entries = (*total);
	trn->ptr_trans_names = 1;
	trn->num_entries2 = (*total);
}

/***************************************************************************
make_reply_lookup_sids
 ***************************************************************************/
static void make_reply_lookup_sids(LSA_R_LOOKUP_SIDS *r_l,
				DOM_R_REF *ref, LSA_TRANS_NAME_ENUM *names,
				uint32 mapped_count, uint32 status)
{
	r_l->dom_ref      = ref;
	r_l->names        = names;
	r_l->mapped_count = mapped_count;
	r_l->status       = status;
}

/***************************************************************************
lsa_reply_lookup_sids
 ***************************************************************************/
static void lsa_reply_lookup_sids(prs_struct *rdata,
				int num_entries, DOM_SID2 sid[MAX_LOOKUP_SIDS],
				char *dom_name, DOM_SID *dom_sid,
				DOM_SID *other_sid1, DOM_SID *other_sid2, DOM_SID *other_sid3)
{
	LSA_R_LOOKUP_SIDS r_l;
	DOM_R_REF ref;
	LSA_TRANS_NAME_ENUM names;
	uint32 mapped_count = 0;

	ZERO_STRUCT(r_l);
	ZERO_STRUCT(ref);
	ZERO_STRUCT(names);

	/* set up the LSA Lookup SIDs response */
	make_dom_ref(&ref, dom_name, dom_sid, other_sid1, other_sid2, other_sid3);
	make_lsa_trans_names(&names, num_entries, sid, &mapped_count);
	make_reply_lookup_sids(&r_l, &ref, &names, mapped_count, 0x0);

	/* store the response in the SMB stream */
	lsa_io_r_lookup_sids("", &r_l, rdata, 0);
}

/***************************************************************************
lsa_reply_lookup_rids
 ***************************************************************************/
static void lsa_reply_lookup_rids(prs_struct *rdata,
				int num_entries, uint32 dom_rids[MAX_LOOKUP_SIDS],
				char *dom_name, DOM_SID *dom_sid,
				DOM_SID *other_sid1, DOM_SID *other_sid2, DOM_SID *other_sid3)
{
	LSA_R_LOOKUP_RIDS r_l;

	ZERO_STRUCT(r_l);

	/* set up the LSA Lookup RIDs response */
	make_reply_lookup_rids(&r_l, num_entries, dom_rids,
				dom_name, dom_sid, other_sid1, other_sid2, other_sid3);
	r_l.status = 0x0;

	/* store the response in the SMB stream */
	lsa_io_r_lookup_rids("", &r_l, rdata, 0);
}

/***************************************************************************
api_lsa_open_policy
 ***************************************************************************/
static void api_lsa_open_policy( int uid, prs_struct *data,
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
static void api_lsa_enum_trust_dom( int uid, prs_struct *data,
                                    prs_struct *rdata )
{
	LSA_Q_ENUM_TRUST_DOM q_e;

	ZERO_STRUCT(q_e);

	/* grab the enum trust domain context etc. */
	lsa_io_q_enum_trust_dom("", &q_e, data, 0);

	/* construct reply.  return status is always 0x0 */
	lsa_reply_enum_trust_dom(&q_e, rdata,
	                                      0, NULL, NULL);
}

/***************************************************************************
api_lsa_query_info
 ***************************************************************************/
static void api_lsa_query_info( int uid, prs_struct *data,
                                prs_struct *rdata )
{
	LSA_Q_QUERY_INFO q_i;
	pstring dom_name;

	ZERO_STRUCT(q_i);

	/* grab the info class and policy handle */
	lsa_io_q_query("", &q_i, data, 0);

	pstrcpy(dom_name, lp_workgroup());

	/* construct reply.  return status is always 0x0 */
	lsa_reply_query_info(&q_i, rdata, dom_name, &global_machine_sid);
}

/***************************************************************************
api_lsa_lookup_sids
 ***************************************************************************/
static void api_lsa_lookup_sids( int uid, prs_struct *data,
                                 prs_struct *rdata )
{
	LSA_Q_LOOKUP_SIDS q_l;
	pstring dom_name;
	DOM_SID sid_S_1_1;
	DOM_SID sid_S_1_3;
	DOM_SID sid_S_1_5;

	ZERO_STRUCT(q_l);
	ZERO_STRUCT(sid_S_1_1);
	ZERO_STRUCT(sid_S_1_3);
	ZERO_STRUCT(sid_S_1_5);

	/* grab the info class and policy handle */
	lsa_io_q_lookup_sids("", &q_l, data, 0);

	pstrcpy(dom_name, lp_workgroup());

	string_to_sid(&sid_S_1_1, "S-1-1");
        string_to_sid(&sid_S_1_3, "S-1-3");
        string_to_sid(&sid_S_1_5, "S-1-5");

	/* construct reply.  return status is always 0x0 */
	lsa_reply_lookup_sids(rdata,
                              q_l.sids.num_entries, q_l.sids.sid, /* SIDs */
                              dom_name, &global_machine_sid, /* domain name, domain SID */
                              &sid_S_1_1, &sid_S_1_3, &sid_S_1_5); /* the three other SIDs */
}

/***************************************************************************
api_lsa_lookup_names
 ***************************************************************************/
static void api_lsa_lookup_names( int uid, prs_struct *data,
                                  prs_struct *rdata )
{
	int i;
	LSA_Q_LOOKUP_RIDS q_l;
	pstring dom_name;
	DOM_SID sid_S_1_1;
	DOM_SID sid_S_1_3;
	DOM_SID sid_S_1_5;
	uint32 dom_rids[MAX_LOOKUP_SIDS];
	uint32 dummy_g_rid;

	ZERO_STRUCT(q_l);
	ZERO_STRUCT(sid_S_1_1);
	ZERO_STRUCT(sid_S_1_3);
	ZERO_STRUCT(sid_S_1_5);
	ZERO_STRUCT(dom_rids);	

	/* grab the info class and policy handle */
	lsa_io_q_lookup_rids("", &q_l, data, 0);

	pstrcpy(dom_name, lp_workgroup());

	string_to_sid(&sid_S_1_1, "S-1-1");
        string_to_sid(&sid_S_1_3, "S-1-3");
        string_to_sid(&sid_S_1_5, "S-1-5");

	/* convert received RIDs to strings, so we can do them. */
	for (i = 0; i < q_l.num_entries; i++)
	{
        fstring user_name;
		fstrcpy(user_name, unistr2(q_l.lookup_name[i].str.buffer));
        /*
         * Map to the UNIX username.
         */
        map_username(user_name);

        /*
         * Do any case conversions.
         */
        (void)Get_Pwnam(user_name, True);

		if (!pdb_name_to_rid(user_name, &dom_rids[i], &dummy_g_rid))
		{
			/* WHOOPS!  we should really do something about this... */
			dom_rids[i] = 0;
		}
	}

	/* construct reply.  return status is always 0x0 */
	lsa_reply_lookup_rids(rdata,
                              q_l.num_entries, dom_rids, /* text-converted SIDs */
                              dom_name, &global_machine_sid, /* domain name, domain SID */
                              &sid_S_1_1, &sid_S_1_3, &sid_S_1_5); /* the three other SIDs */
}

/***************************************************************************
 api_lsa_close
 ***************************************************************************/
static void api_lsa_close( int uid, prs_struct *data,
                                  prs_struct *rdata)
{
	/* XXXX this is NOT good */
	char *q = mem_data(&(rdata->data), rdata->offset);

	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0); q += 4;

	rdata->offset += 24;
}

/***************************************************************************
 api_lsa_open_secret
 ***************************************************************************/
static void api_lsa_open_secret( int uid, prs_struct *data,
                                  prs_struct *rdata)
{
	/* XXXX this is NOT good */
	char *q = mem_data(&(rdata->data), rdata->offset);

	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0); q += 4;
	SIVAL(q, 0, 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND); q += 4;
	
	rdata->offset += 24;
}

/***************************************************************************
 \PIPE\ntlsa commands
 ***************************************************************************/
static struct api_struct api_lsa_cmds[] =
{
	{ "LSA_OPENPOLICY"      , LSA_OPENPOLICY      , api_lsa_open_policy    },
	{ "LSA_QUERYINFOPOLICY" , LSA_QUERYINFOPOLICY , api_lsa_query_info     },
	{ "LSA_ENUMTRUSTDOM"    , LSA_ENUMTRUSTDOM    , api_lsa_enum_trust_dom },
	{ "LSA_CLOSE"           , LSA_CLOSE           , api_lsa_close          },
	{ "LSA_OPENSECRET"      , LSA_OPENSECRET      , api_lsa_open_secret    },
	{ "LSA_LOOKUPSIDS"      , LSA_LOOKUPSIDS      , api_lsa_lookup_sids    },
	{ "LSA_LOOKUPNAMES"     , LSA_LOOKUPNAMES     , api_lsa_lookup_names   },
	{ NULL                  , 0                   , NULL                   }
};

/***************************************************************************
 api_ntLsarpcTNP
 ***************************************************************************/
BOOL api_ntlsa_rpc(pipes_struct *p, prs_struct *data)
{
	return api_rpcTNP(p, "api_ntlsa_rpc", api_lsa_cmds, data);
}

