
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
	init_unistr2(&(d_q->uni_domain_name), dom_name, domlen);

	init_dom_sid2(&(d_q->dom_sid), dom_sid);
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
	init_r_enum_trust_dom(&r_e, enum_context, dom_name, dom_sid,
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
 ***************************************************************************/
static void make_dom_ref(DOM_R_REF *ref, int num_domains,
				char **dom_names, DOM_SID **dom_sids)
                         
{
	int i;

	if (num_domains > MAX_REF_DOMAINS)
	{
		num_domains = MAX_REF_DOMAINS;
	}

	ref->undoc_buffer = 1;
	ref->num_ref_doms_1 = num_domains;
	ref->undoc_buffer2 = 1;
	ref->max_entries = MAX_REF_DOMAINS;
	ref->num_ref_doms_2 = num_domains;

	for (i = 0; i < num_domains; i++)
	{
		int len = dom_names[i] != NULL ? strlen(dom_names[i]) : 0;

		init_uni_hdr(&(ref->hdr_ref_dom[i].hdr_dom_name), len, len, len != 0 ? 1 : 0);
		ref->hdr_ref_dom[i].ptr_dom_sid = dom_sids[i] != NULL ? 1 : 0;

		init_unistr2 (&(ref->ref_dom[i].uni_dom_name), dom_names[i], len);
		init_dom_sid2(&(ref->ref_dom[i].ref_dom     ), dom_sids [i]);
	}

}

/***************************************************************************
make_reply_lookup_rids
 ***************************************************************************/
static void make_reply_lookup_rids(LSA_R_LOOKUP_RIDS *r_l,
				int num_entries, uint32 dom_rids[MAX_LOOKUP_SIDS],
				int num_ref_doms,
				char **dom_names, DOM_SID **dom_sids)
{
	int i;

	make_dom_ref(&(r_l->dom_ref), num_ref_doms, dom_names, dom_sids);

	r_l->num_entries = num_entries;
	r_l->undoc_buffer = 1;
	r_l->num_entries2 = num_entries;

	SMB_ASSERT_ARRAY(r_l->dom_rid, num_entries);

	for (i = 0; i < num_entries; i++)
	{
		init_dom_rid2(&(r_l->dom_rid[i]), dom_rids[i], 0x01);
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

	SMB_ASSERT(num_entries <= MAX_LOOKUP_SIDS);

	for (i = 0; i < num_entries; i++)
	{
		uint32 rid = 0xffffffff;
		uint8 num_auths = sid[i].sid.num_auths;
		fstring name;
		uint32 type;
		
		SMB_ASSERT_ARRAY(sid[i].sid.sub_auths, num_auths);

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
			init_lsa_trans_name(&(trn->name    [(*total)]),
			                    &(trn->uni_name[(*total)]),
			                    type, name, (*total));
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
				int num_ref_doms,
				char **dom_names, DOM_SID **dom_sids)
{
	LSA_R_LOOKUP_SIDS r_l;
	DOM_R_REF ref;
	LSA_TRANS_NAME_ENUM names;
	uint32 mapped_count = 0;

	ZERO_STRUCT(r_l);
	ZERO_STRUCT(ref);
	ZERO_STRUCT(names);

	/* set up the LSA Lookup SIDs response */
	make_dom_ref(&ref, num_ref_doms, dom_names, dom_sids);
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
				int num_ref_doms,
				char **dom_names, DOM_SID **dom_sids)
{
	LSA_R_LOOKUP_RIDS r_l;

	ZERO_STRUCT(r_l);

	/* set up the LSA Lookup RIDs response */
	make_reply_lookup_rids(&r_l, num_entries, dom_rids,
				num_ref_doms, dom_names, dom_sids);
	r_l.status = 0x0;

	/* store the response in the SMB stream */
	lsa_io_r_lookup_rids("", &r_l, rdata, 0);
}

/***************************************************************************
api_lsa_open_policy
 ***************************************************************************/
static BOOL api_lsa_open_policy2( uint16 vuid, prs_struct *data,
                             prs_struct *rdata )
{
	LSA_Q_OPEN_POL2 q_o;

	ZERO_STRUCT(q_o);

	/* grab the server, object attributes and desired access flag...*/
	lsa_io_q_open_pol2("", &q_o, data, 0);

	/* lkclXXXX having decoded it, ignore all fields in the open policy! */

	/* return a 20 byte policy handle */
	lsa_reply_open_policy2(rdata);

	return True;
}

/***************************************************************************
api_lsa_open_policy
 ***************************************************************************/
static BOOL api_lsa_open_policy( uint16 vuid, prs_struct *data,
                             prs_struct *rdata )
{
	LSA_Q_OPEN_POL q_o;

	ZERO_STRUCT(q_o);

	/* grab the server, object attributes and desired access flag...*/
	lsa_io_q_open_pol("", &q_o, data, 0);

	/* lkclXXXX having decoded it, ignore all fields in the open policy! */

	/* return a 20 byte policy handle */
	lsa_reply_open_policy(rdata);

	return True;
}

/***************************************************************************
api_lsa_enum_trust_dom
 ***************************************************************************/
static BOOL api_lsa_enum_trust_dom( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	LSA_Q_ENUM_TRUST_DOM q_e;

	ZERO_STRUCT(q_e);

	/* grab the enum trust domain context etc. */
	lsa_io_q_enum_trust_dom("", &q_e, data, 0);

	/* construct reply.  return status is always 0x0 */
	lsa_reply_enum_trust_dom(&q_e, rdata, 0, NULL, NULL);

	return True;
}

/***************************************************************************
api_lsa_query_info
 ***************************************************************************/
static BOOL api_lsa_query_info( uint16 vuid, prs_struct *data,
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

	return True;
}

/***************************************************************************
api_lsa_lookup_sids
 ***************************************************************************/
static BOOL api_lsa_lookup_sids( uint16 vuid, prs_struct *data,
                                 prs_struct *rdata )
{
	LSA_Q_LOOKUP_SIDS q_l;
	pstring dom_name;
	DOM_SID sid_S_1_1;
	DOM_SID sid_S_1_3;
	DOM_SID sid_S_1_5;

	DOM_SID *sid_array[4];
	char    *dom_names[4];

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

	dom_names[0] = dom_name;
	sid_array[0] = &global_sam_sid;

	dom_names[1] = "Everyone";
	sid_array[1] = &sid_S_1_1;

	dom_names[2] = "don't know";
	sid_array[2] = &sid_S_1_3;

	dom_names[3] = "NT AUTHORITY";
	sid_array[3] = &sid_S_1_5;

	/* construct reply.  return status is always 0x0 */
	lsa_reply_lookup_sids(rdata,
                              q_l.sids.num_entries, q_l.sids.sid, /* SIDs */
                              4, dom_names, sid_array);

	return True;
}

/***************************************************************************
api_lsa_lookup_names
 ***************************************************************************/
static BOOL api_lsa_lookup_names( uint16 vuid, prs_struct *data,
                                  prs_struct *rdata )
{
	int i;
	LSA_Q_LOOKUP_RIDS q_l;
	pstring dom_name;
	uint32 dom_rids[MAX_LOOKUP_SIDS];
	uint32 dummy_g_rid;

	DOM_SID sid_S_1_1;
	DOM_SID sid_S_1_3;
	DOM_SID sid_S_1_5;

	DOM_SID *sid_array[4];
	char    *dom_names[4];

	ZERO_STRUCT(q_l);
	ZERO_STRUCT(sid_S_1_1);
	ZERO_STRUCT(sid_S_1_3);
	ZERO_STRUCT(sid_S_1_5);
	ZERO_ARRAY(dom_rids);	

	/* grab the info class and policy handle */
	lsa_io_q_lookup_rids("", &q_l, data, 0);

	pstrcpy(dom_name, lp_workgroup());

	string_to_sid(&sid_S_1_1, "S-1-1");
        string_to_sid(&sid_S_1_3, "S-1-3");
        string_to_sid(&sid_S_1_5, "S-1-5");

	dom_names[0] = dom_name;
	sid_array[0] = &global_sam_sid;

	dom_names[1] = "Everyone";
	sid_array[1] = &sid_S_1_1;

	dom_names[2] = "don't know";
	sid_array[2] = &sid_S_1_3;

	dom_names[3] = "NT AUTHORITY";
	sid_array[3] = &sid_S_1_5;

	SMB_ASSERT_ARRAY(q_l.lookup_name, q_l.num_entries);

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
                              4, dom_names, sid_array);

	return True;
}

/***************************************************************************
 api_lsa_close
 ***************************************************************************/
static BOOL api_lsa_close( uint16 vuid, prs_struct *data,
                                  prs_struct *rdata)
{
	/* XXXX this is NOT good */
	size_t i;
	uint32 dummy = 0;

	for(i =0; i < 5; i++) {
		if(!prs_uint32("api_lsa_close", rdata, 1, &dummy)) {
			DEBUG(0,("api_lsa_close: prs_uint32 %d failed.\n",
				(int)i ));
			return False;
		}
	}

	return True;
}

/***************************************************************************
 api_lsa_open_secret
 ***************************************************************************/
static BOOL api_lsa_open_secret( uint16 vuid, prs_struct *data,
                                  prs_struct *rdata)
{
	/* XXXX this is NOT good */
	size_t i;
	uint32 dummy = 0;

	for(i =0; i < 4; i++) {
		if(!prs_uint32("api_lsa_close", rdata, 1, &dummy)) {
			DEBUG(0,("api_lsa_open_secret: prs_uint32 %d failed.\n",
				(int)i ));
			return False;
		}
	}

	dummy = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	if(!prs_uint32("api_lsa_close", rdata, 1, &dummy)) {
		DEBUG(0,("api_lsa_open_secret: prs_uint32 status failed.\n"));
		return False;
	}

	return True;
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
