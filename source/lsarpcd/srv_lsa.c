
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jeremy Allison               1998-2000.
 *  Copyright (C) Elrond                            2000.
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
#include "rpc_parse.h"
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;
extern fstring global_myworkgroup;

/***************************************************************************
make_dom_query
 ***************************************************************************/
static void make_dom_query(DOM_QUERY *d_q, char *dom_name, DOM_SID *dom_sid)
{
	fstring sid_str;
	int domlen = strlen(dom_name);

	d_q->uni_dom_str_len = (domlen+1) * 2;
	d_q->uni_dom_max_len = domlen * 2;

	d_q->buffer_dom_name = domlen  != 0    ? 1 : 0; /* domain buffer pointer */
	d_q->buffer_dom_sid  = dom_sid != NULL ? 1 : 0; /* domain sid pointer */

	/* this string is supposed to be character short */
	make_unistr2(&(d_q->uni_domain_name), dom_name, domlen);
	d_q->uni_domain_name.uni_max_len++;

	sid_to_string(sid_str, dom_sid);
	make_dom_sid2(&(d_q->dom_sid), dom_sid);
}

/***************************************************************************
lsa_reply_query_info
 ***************************************************************************/
static void lsa_reply_query_info(LSA_Q_QUERY_INFO *q_q, prs_struct *rdata,
				char *dom_name, DOM_SID *dom_sid,
				uint32 status)
{
	LSA_R_QUERY_INFO r_q;

	ZERO_STRUCT(r_q);

	r_q.status = status;

	if (r_q.status == 0x0 && !find_policy_by_hnd(get_global_hnd_cache(), &q_q->pol))
	{
		r_q.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (r_q.status == 0x0)
	{
		/* set up the LSA QUERY INFO response */

		r_q.undoc_buffer = 0x1; 
		r_q.info_class = q_q->info_class;

		make_dom_query(&r_q.dom.id5, dom_name, dom_sid);

		r_q.status = 0x0;
	}
	/* store the response in the SMB stream */
	lsa_io_r_query("", &r_q, rdata, 0);
}


/***************************************************************************
make_lsa_rid2s
 ***************************************************************************/
static uint32 get_remote_sid(const char *dom_name, char *find_name,
			     DOM_SID *sid, uint32 *rid, uint32 *sid_name_use)
{
	fstring srv_name;
	fstring dummy;
	uint32 status;

	DEBUG(10, ("lookup remote name: %s %s\n",
	           dom_name, find_name));

	if (! get_any_dc_name(dom_name, srv_name))
	{
		return 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}
	if (strequal(srv_name, "\\\\."))
	{
		DEBUG(0, ("WARNING: infinite loop in lsarpcd !\n"));
		return 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}

	status = lookup_lsa_name(dom_name, find_name,
				 sid, sid_name_use);

	if (status == 0x0 &&
	   (!sid_split_rid(sid, rid) ||
	    !map_domain_sid_to_name(sid, dummy)))
	{
		status = 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}
	return status;
}

static void make_lsa_rid2s(DOM_R_REF *ref,
				DOM_RID2 *rid2,
				int num_entries, UNISTR2 name[MAX_LOOKUP_SIDS],
				uint32 *mapped_count)
{
	int i;
	int total = 0;
	(*mapped_count) = 0;

	SMB_ASSERT(num_entries <= MAX_LOOKUP_SIDS);

	for (i = 0; i < num_entries; i++)
	{
		uint32 status = 0x0;
		DOM_SID find_sid;
		DOM_SID sid;
		uint32 rid = 0xffffffff;
		int dom_idx = -1;
		char *find_name = NULL;
		fstring dom_name;
		fstring full_name;
		uint32 sid_name_use = SID_NAME_UNKNOWN;

		unistr2_to_ascii(full_name, &name[i], sizeof(full_name)-1);
		find_name = strdup(full_name);

		if (!split_domain_name(full_name, dom_name, find_name))
		{
			status = 0xC0000000 | NT_STATUS_NONE_MAPPED;
		}
		if (status == 0x0 && map_domain_name_to_sid(&find_sid,
		                                            &find_name))
		{
			sid_name_use = SID_NAME_DOMAIN;
			dom_idx = make_dom_ref(ref, dom_name, &find_sid);
			rid = 0xffffffff;
			sid_copy(&sid, &find_sid);
		}
		else if (status == 0x0)
		{
			uint32 ret;
			ret = lookup_sam_domainname("\\\\.",
						    dom_name, &find_sid);

			if (ret == 0x0)
			{
				pstring tmp;
				sid_to_string(tmp, &find_sid);
				DEBUG(10,("lookup sam name: %s %s\n",
				           tmp, find_name));
				status = lookup_sam_name(NULL,
				                         &find_sid,
				                         find_name,
							 &rid, &sid_name_use);
				sid_copy(&sid, &find_sid);
			}
			else
			{
				status = get_remote_sid(dom_name, find_name,
							&sid, &rid,
							&sid_name_use);
			}
		}

		if (status == 0x0)
		{
			dom_idx = make_dom_ref(ref, find_name, &sid);
		}

		if (status == 0x0)
		{
			(*mapped_count)++;
		}
		else
		{
			dom_idx = -1;
			rid = 0xffffffff;
			sid_name_use = SID_NAME_UNKNOWN;
		}

		make_dom_rid2(&rid2[total], rid, sid_name_use, dom_idx);
		total++;

		if (find_name != NULL)
		{
			free(find_name);
		}
	}
}

/***************************************************************************
make_reply_lookup_names
 ***************************************************************************/
static void make_reply_lookup_names(LSA_R_LOOKUP_NAMES *r_l,
				DOM_R_REF *ref, uint32 num_entries,
				DOM_RID2 *rid2, uint32 mapped_count)
{
	r_l->ptr_dom_ref  = 1;
	r_l->dom_ref      = ref;

	r_l->num_entries  = num_entries;
	r_l->ptr_entries  = 1;
	r_l->num_entries2 = num_entries;
	r_l->dom_rid      = rid2;

	r_l->mapped_count = mapped_count;

	if (mapped_count == 0)
	{
		r_l->status = 0xC0000000 | NT_STATUS_NONE_MAPPED;
	}
	else
	{
		r_l->status = 0x0;
	}
}

/***************************************************************************
make_reply_lookup_sids
 ***************************************************************************/
static void make_reply_lookup_sids(LSA_R_LOOKUP_SIDS *r_l,
				DOM_R_REF *ref, LSA_TRANS_NAME_ENUM *names,
				uint32 mapped_count, uint32 status)
{
	r_l->ptr_dom_ref  = 1;
	r_l->dom_ref      = ref;
	r_l->names        = names;
	r_l->mapped_count = mapped_count;
	r_l->status       = status;
}

/***************************************************************************
lsa_reply_lookup_sids
 ***************************************************************************/
static void lsa_reply_lookup_sids(LSA_Q_LOOKUP_SIDS *q_l, prs_struct *rdata)
{
	LSA_R_LOOKUP_SIDS r_l;
	DOM_R_REF ref;
	LSA_TRANS_NAME_ENUM names;
	uint32 mapped_count = 0;
	DOM_SID2 *sid = q_l->sids.sid;
	int num_entries = q_l->sids.num_entries;
	uint32 status;

	ZERO_STRUCT(r_l);
	ZERO_STRUCT(ref);
	ZERO_STRUCT(names);

	/* set up the LSA Lookup SIDs response */
	status = _lsa_lookup_sids(&q_l->pol,
				  num_entries, sid, &q_l->level,
				  &ref, &names, &mapped_count);
	make_reply_lookup_sids(&r_l, &ref, &names, mapped_count, status);

	/* store the response in the SMB stream */
	lsa_io_r_lookup_sids("", &r_l, rdata, 0);
}

/***************************************************************************
lsa_reply_lookup_names
 ***************************************************************************/
static void lsa_reply_lookup_names(prs_struct *rdata,
				UNISTR2 names[MAX_LOOKUP_SIDS], int num_entries)
{
	LSA_R_LOOKUP_NAMES r_l;
	DOM_R_REF ref;
	DOM_RID2 rids[MAX_LOOKUP_SIDS];
	uint32 mapped_count = 0;

	ZERO_STRUCT(r_l);
	ZERO_STRUCT(ref);
	ZERO_STRUCT(rids);

	/* set up the LSA Lookup RIDs response */
	make_lsa_rid2s(&ref, rids, num_entries, names, &mapped_count);
	make_reply_lookup_names(&r_l, &ref, num_entries, rids, mapped_count);

	/* store the response in the SMB stream */
	lsa_io_r_lookup_names("", &r_l, rdata, 0);
}

/***************************************************************************
api_lsa_open_policy
 ***************************************************************************/
static void api_lsa_open_policy2( rpcsrv_struct *p, prs_struct *data,
                             prs_struct *rdata )
{
	LSA_Q_OPEN_POL2 q_o;
	LSA_R_OPEN_POL2 r_o;

	ZERO_STRUCT(q_o);
	ZERO_STRUCT(r_o);

	lsa_io_q_open_pol2("", &q_o, data, 0);
	r_o.status = _lsa_open_policy2(&q_o.uni_server_name, &r_o.pol,
				       &q_o.attr,
				       q_o.des_access);
	lsa_io_r_open_pol2("", &r_o, rdata, 0);
}

/***************************************************************************
api_lsa_open_policy
 ***************************************************************************/
static void api_lsa_open_policy( rpcsrv_struct *p, prs_struct *data,
                             prs_struct *rdata )
{
	LSA_Q_OPEN_POL q_o;
	LSA_R_OPEN_POL r_o;

	ZERO_STRUCT(r_o);
	ZERO_STRUCT(q_o);

	lsa_io_q_open_pol("", &q_o, data, 0);
	r_o.status = _lsa_open_policy(NULL, &r_o.pol,
	                              &q_o.attr, q_o.des_access);
	lsa_io_r_open_pol("", &r_o, rdata, 0);
}

/***************************************************************************
api_lsa_enum_trust_dom
 ***************************************************************************/
static void api_lsa_enum_trust_dom( rpcsrv_struct *p, prs_struct *data,
                                    prs_struct *rdata )
{
	uint32 status;
	uint32 enum_context;
	uint32 num_doms = 0;
	UNISTR2 *uni_names = NULL;
	DOM_SID **sids = NULL;
	LSA_R_ENUM_TRUST_DOM r_e;
	LSA_Q_ENUM_TRUST_DOM q_e;

	ZERO_STRUCT(r_e);
	ZERO_STRUCT(q_e);

	/* grab the enum trust domain context etc. */
	lsa_io_q_enum_trust_dom("", &q_e, data, 0);

	/* construct reply.  return status is always 0x0 */

	status = _lsa_enum_trust_dom(NULL, &enum_context, &num_doms,
				     &uni_names, &sids);

	make_r_enum_trust_dom(&r_e, enum_context,
			      num_doms, uni_names, sids,
			      status);

	/* store the response in the SMB stream */
	lsa_io_r_enum_trust_dom("", &r_e, rdata, 0);

	/* free names and sids */
	free_sid_array(num_doms, sids);
	safe_free(uni_names);
}

/***************************************************************************
api_lsa_query_info
 ***************************************************************************/
static void api_lsa_query_info( rpcsrv_struct *p, prs_struct *data,
                                prs_struct *rdata )
{
	LSA_Q_QUERY_INFO q_i;
	fstring name;
	uint32 status = 0x0;
	DOM_SID sid;

	memset(name, 0, sizeof(name));
	ZERO_STRUCT(sid);
	ZERO_STRUCT(q_i);

	/* grab the info class and policy handle */
	lsa_io_q_query("", &q_i, data, 0);

	status = _lsa_query_info_pol(&q_i.pol, q_i.info_class,
				     name, &sid);

	/* construct reply.  return status is always 0x0 */
	lsa_reply_query_info(&q_i, rdata, name, &sid, status);
}

/***************************************************************************
api_lsa_lookup_sids
 ***************************************************************************/
static void api_lsa_lookup_sids( rpcsrv_struct *p, prs_struct *data,
                                 prs_struct *rdata )
{
	LSA_Q_LOOKUP_SIDS q_l;
	ZERO_STRUCT(q_l);

	/* grab the info class and policy handle */
	lsa_io_q_lookup_sids("", &q_l, data, 0);

	/* construct reply.  return status is always 0x0 */
	lsa_reply_lookup_sids(&q_l, rdata);
}

/***************************************************************************
api_lsa_lookup_names
 ***************************************************************************/
static void api_lsa_lookup_names( rpcsrv_struct *p, prs_struct *data,
                                  prs_struct *rdata )
{
	LSA_Q_LOOKUP_NAMES q_l;
	ZERO_STRUCT(q_l);

	/* grab the info class and policy handle */
	lsa_io_q_lookup_names("", &q_l, data, 0);

	SMB_ASSERT_ARRAY(q_l.uni_name, q_l.num_entries);

	lsa_reply_lookup_names(rdata, q_l.uni_name, q_l.num_entries);
}

/***************************************************************************
 api_lsa_close
 ***************************************************************************/
static void api_lsa_close( rpcsrv_struct *p, prs_struct *data,
                                  prs_struct *rdata)
{
	LSA_R_CLOSE r_c;
	LSA_Q_CLOSE q_c;

	ZERO_STRUCT(q_c);
	ZERO_STRUCT(r_c);

	lsa_io_q_close("", &q_c, data, 0);
	r_c.status = _lsa_close(&q_c.pol);
	lsa_io_r_close("", &r_c, rdata, 0);
}

/***************************************************************************
 api_lsa_create_secret
 ***************************************************************************/
static void api_lsa_create_secret( rpcsrv_struct *p, prs_struct *data,
                                  prs_struct *rdata)
{
	LSA_R_CREATE_SECRET r_o;
	LSA_Q_CREATE_SECRET q_o;

	ZERO_STRUCT(q_o);
	ZERO_STRUCT(r_o);

	lsa_io_q_create_secret("", &q_o, data, 0);
	r_o.status = _lsa_create_secret(&q_o.pol,
				      &q_o.uni_secret, q_o.des_access,
				      &r_o.pol);
	lsa_io_r_create_secret("", &r_o, rdata, 0);
}

/***************************************************************************
 api_lsa_set_secret.  AGH!  HACK! :)
 ***************************************************************************/
static void api_lsa_set_secret( rpcsrv_struct *p, prs_struct *data,
                                  prs_struct *rdata)
{
	LSA_Q_SET_SECRET q_o;
	LSA_R_SET_SECRET r_o;
	STRING2 *val = NULL;

	ZERO_STRUCT(r_o);
	ZERO_STRUCT(q_o);

	lsa_io_q_set_secret("", &q_o, data, 0);
	if (q_o.value.ptr_secret) val = &q_o.value.enc_secret;

	r_o.status = _lsa_set_secret(&q_o.pol, val, q_o.unknown);

	lsa_io_r_set_secret("", &r_o, rdata, 0);
}

/***************************************************************************
 api_lsa_query_secret.  AGH!  HACK! :)
 ***************************************************************************/
static void api_lsa_query_secret( rpcsrv_struct *p, prs_struct *data,
                                  prs_struct *rdata)
{
	LSA_R_QUERY_SECRET r_o;
	LSA_Q_QUERY_SECRET q_o;
	NTTIME *curtim = NULL;
	NTTIME *oldtim = NULL;
	STRING2 *curval = NULL;
	STRING2 *oldval = NULL;

	ZERO_STRUCT(r_o);
	ZERO_STRUCT(q_o);

	lsa_io_q_query_secret("", &q_o, data, 0);

	/* HACK! */
	if (q_o.sec.curinfo.ptr_value  != 0) curval = &q_o.sec.curinfo.value.enc_secret;
	if (q_o.sec.curinfo.ptr_update != 0) curtim = &q_o.sec.curinfo.last_update;
	if (q_o.sec.oldinfo.ptr_value  != 0) oldval = &q_o.sec.oldinfo.value.enc_secret;
	if (q_o.sec.oldinfo.ptr_update != 0) oldtim = &q_o.sec.oldinfo.last_update;

	r_o.status = _lsa_query_secret(&q_o.pol,
	                                curval, curtim,
	                                oldval, oldtim);

	memcpy(&r_o.sec, &q_o.sec, sizeof(r_o.sec)); /* urgh! HACK! */
	if (r_o.sec.curinfo.ptr_value != 0) /* MORE HACK! */
	{
		r_o.sec.curinfo.value.ptr_secret = 1;
		make_strhdr2(&r_o.sec.curinfo.value.hdr_secret,
		              r_o.sec.curinfo.value.enc_secret.str_str_len,
		              r_o.sec.curinfo.value.enc_secret.str_max_len, 1);
	}
	if (r_o.sec.oldinfo.ptr_value != 0) /* MORE HACK! */
	{
		r_o.sec.curinfo.value.ptr_secret = 1;
		make_strhdr2(&r_o.sec.oldinfo.value.hdr_secret,
		              r_o.sec.oldinfo.value.enc_secret.str_str_len,
		              r_o.sec.oldinfo.value.enc_secret.str_max_len, 1);
	}

	lsa_io_r_query_secret("", &r_o, rdata, 0);
}

/***************************************************************************
 api_lsa_create_secret
 ***************************************************************************/
static void api_lsa_open_secret( rpcsrv_struct *p, prs_struct *data,
                                  prs_struct *rdata)
{
	LSA_R_OPEN_SECRET r_o;
	LSA_Q_OPEN_SECRET q_o;

	ZERO_STRUCT(r_o);
	ZERO_STRUCT(q_o);

	lsa_io_q_open_secret("", &q_o, data, 0);
	r_o.status = _lsa_open_secret(&q_o.pol,
				      &q_o.uni_secret, q_o.des_access,
				      &r_o.pol);
	lsa_io_r_open_secret("", &r_o, rdata, 0);
}

/***************************************************************************
 \PIPE\ntlsa commands
 ***************************************************************************/
static const struct api_struct api_lsa_cmds[] =
{
	{ "LSA_OPENPOLICY2"    , LSA_OPENPOLICY2    , api_lsa_open_policy2   },
	{ "LSA_OPENPOLICY"     , LSA_OPENPOLICY     , api_lsa_open_policy    },
	{ "LSA_QUERYINFOPOLICY", LSA_QUERYINFOPOLICY, api_lsa_query_info     },
	{ "LSA_ENUMTRUSTDOM"   , LSA_ENUMTRUSTDOM   , api_lsa_enum_trust_dom },
	{ "LSA_CLOSE"          , LSA_CLOSE          , api_lsa_close          },
	{ "LSA_OPENSECRET"     , LSA_OPENSECRET     , api_lsa_open_secret    },
	{ "LSA_CREATESECRET"   , LSA_CREATESECRET   , api_lsa_create_secret  },
	{ "LSA_QUERYSECRET"    , LSA_QUERYSECRET    , api_lsa_query_secret   },
	{ "LSA_SETSECRET"      , LSA_SETSECRET      , api_lsa_set_secret     },
	{ "LSA_LOOKUPSIDS"     , LSA_LOOKUPSIDS     , api_lsa_lookup_sids    },
	{ "LSA_LOOKUPNAMES"    , LSA_LOOKUPNAMES    , api_lsa_lookup_names   },
	{ NULL                 , 0                  , NULL                   }
};

/***************************************************************************
 api_ntLsarpcTNP
 ***************************************************************************/
BOOL api_ntlsa_rpc(rpcsrv_struct *p)
{
	return api_rpcTNP(p, "api_ntlsa_rpc", api_lsa_cmds);
}
