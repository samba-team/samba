
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
make_reply_lookup_names
 ***************************************************************************/
static void make_reply_lookup_names(LSA_R_LOOKUP_NAMES * r_l,
				    DOM_R_REF * ref, uint32 num_entries,
				    DOM_RID2 * rid2, uint32 mapped_count,
				    uint32 status)
{
	r_l->ptr_dom_ref = (ref != NULL ? 1 : 0);
	r_l->dom_ref = ref;

	if (rid2 == NULL)
		num_entries = 0;

	r_l->num_entries = num_entries;
	r_l->ptr_entries = (rid2 != NULL ? 1 : 0);
	r_l->num_entries2 = num_entries;
	r_l->dom_rid = rid2;

	r_l->mapped_count = mapped_count;

	r_l->status = status;
}

/***************************************************************************
make_reply_lookup_sids
 ***************************************************************************/
static void make_reply_lookup_sids(LSA_R_LOOKUP_SIDS * r_l,
				   DOM_R_REF * ref,
				   LSA_TRANS_NAME_ENUM * names,
				   uint32 mapped_count, uint32 status)
{
	r_l->ptr_dom_ref = 1;
	r_l->dom_ref = ref;
	r_l->names = names;
	r_l->mapped_count = mapped_count;
	r_l->status = status;
}

/***************************************************************************
lsa_reply_lookup_sids
 ***************************************************************************/
static BOOL lsa_reply_lookup_sids(LSA_Q_LOOKUP_SIDS * q_l, prs_struct *rdata)
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
	return lsa_io_r_lookup_sids("", &r_l, rdata, 0);
}


/***************************************************************************
api_lsa_open_policy
 ***************************************************************************/
static BOOL api_lsa_open_policy2(prs_struct *data, prs_struct *rdata)
{
	LSA_Q_OPEN_POL2 q_o;
	LSA_R_OPEN_POL2 r_o;

	ZERO_STRUCT(q_o);
	ZERO_STRUCT(r_o);

	if (!lsa_io_q_open_pol2("", &q_o, data, 0))
	{
		return False;
	}

	r_o.status = _lsa_open_policy2(&q_o.uni_server_name, &r_o.pol,
				       &q_o.attr, q_o.des_access);
	return lsa_io_r_open_pol2("", &r_o, rdata, 0);
}

/***************************************************************************
api_lsa_open_policy
 ***************************************************************************/
static BOOL api_lsa_open_policy(prs_struct *data, prs_struct *rdata)
{
	LSA_Q_OPEN_POL q_o;
	LSA_R_OPEN_POL r_o;

	ZERO_STRUCT(r_o);
	ZERO_STRUCT(q_o);

	if (!lsa_io_q_open_pol("", &q_o, data, 0))
	{
		return False;
	}

	r_o.status = _lsa_open_policy(NULL, &r_o.pol,
				      &q_o.attr, q_o.des_access);
	return lsa_io_r_open_pol("", &r_o, rdata, 0);
}

/***************************************************************************
api_lsa_enum_trust_dom
 ***************************************************************************/
static BOOL api_lsa_enum_trust_dom(prs_struct *data, prs_struct *rdata)
{
	uint32 status;
	uint32 enum_context;
	uint32 num_doms = 0;
	UNISTR2 *uni_names = NULL;
	DOM_SID **sids = NULL;
	LSA_R_ENUM_TRUST_DOM r_e;
	LSA_Q_ENUM_TRUST_DOM q_e;
	BOOL ret;

	ZERO_STRUCT(r_e);
	ZERO_STRUCT(q_e);

	/* grab the enum trust domain context etc. */
	if (!lsa_io_q_enum_trust_dom("", &q_e, data, 0))
	{
		return False;
	}

	/* construct reply.  return status is always 0x0 */

	status = _lsa_enum_trust_dom(NULL, &enum_context, &num_doms,
				     &uni_names, &sids);

	make_r_enum_trust_dom(&r_e, enum_context,
			      num_doms, uni_names, sids, status);

	/* store the response in the SMB stream */
	ret = lsa_io_r_enum_trust_dom("", &r_e, rdata, 0);

	/* free names and sids */
	free_sid_array(num_doms, sids);
	safe_free(uni_names);

	return ret;
}

/***************************************************************************
api_lsa_query_info
 ***************************************************************************/
static BOOL api_lsa_query_info(prs_struct *data, prs_struct *rdata)
{
	LSA_Q_QUERY_INFO q_i;
	LSA_R_QUERY_INFO r_i;
	fstring name;
	DOM_SID sid;

	memset(name, 0, sizeof(name));
	ZERO_STRUCT(sid);
	ZERO_STRUCT(q_i);
	ZERO_STRUCT(r_i);

	/* grab the info class and policy handle */
	if (!lsa_io_q_query("", &q_i, data, 0))
	{
		return False;
	}

	r_i.status = _lsa_query_info_pol(&q_i.pol, q_i.info_class,
					 &r_i.dom);

	if (r_i.status == NT_STATUS_NOPROBLEMO)
	{
		/* set up the LSA QUERY INFO response */

		r_i.undoc_buffer = 1;
		r_i.info_class = q_i.info_class;
	}

	/* store the response in the SMB stream */
	return lsa_io_r_query("", &r_i, rdata, 0);
}

/***************************************************************************
api_lsa_set_info
 ***************************************************************************/
static BOOL api_lsa_set_info(prs_struct *data, prs_struct *rdata)
{
	LSA_Q_SET_INFO q_i;

	ZERO_STRUCT(q_i);

	return False;
}

/***************************************************************************
api_lsa_lookup_sids
 ***************************************************************************/
static BOOL api_lsa_lookup_sids(prs_struct *data, prs_struct *rdata)
{
	LSA_Q_LOOKUP_SIDS q_l;
	ZERO_STRUCT(q_l);

	/* grab the info class and policy handle */
	if (!lsa_io_q_lookup_sids("", &q_l, data, 0))
	{
		return False;
	}

	/* construct reply.  return status is always 0x0 */
	return lsa_reply_lookup_sids(&q_l, rdata);
}

/***************************************************************************
api_lsa_lookup_names
 ***************************************************************************/
static BOOL api_lsa_lookup_names(prs_struct *data, prs_struct *rdata)
{
	LSA_Q_LOOKUP_NAMES q_l;
	LSA_R_LOOKUP_NAMES r_l;
	DOM_R_REF ref;
	DOM_RID2 *rids;
	uint32 mapped_count = 0;
	uint32 status;
	uint32 ret;

	ZERO_STRUCT(q_l);
	ZERO_STRUCT(r_l);
	ZERO_STRUCT(ref);
	rids = NULL;

	/* grab the info class and policy handle */
	if (!lsa_io_q_lookup_names("", &q_l, data, 0))
	{
		return False;
	}

	SMB_ASSERT_ARRAY(q_l.uni_name, q_l.num_entries);

	status = _lsa_lookup_names(&q_l.pol,
				   q_l.num_entries, q_l.uni_name,
				   &ref, &rids, &mapped_count);

	make_reply_lookup_names(&r_l, &ref, q_l.num_entries, rids,
				mapped_count, status);

	/* store the response in the SMB stream */
	ret = lsa_io_r_lookup_names("", &r_l, rdata, 0);

	safe_free(rids);

	return ret;
}

/***************************************************************************
 api_lsa_close
 ***************************************************************************/
static BOOL api_lsa_close(prs_struct *data, prs_struct *rdata)
{
	LSA_R_CLOSE r_c;
	LSA_Q_CLOSE q_c;

	ZERO_STRUCT(q_c);
	ZERO_STRUCT(r_c);

	if (!lsa_io_q_close("", &q_c, data, 0))
	{
		return False;
	}

	r_c.pol = q_c.pol;	/* in/out */
	r_c.status = _lsa_close(&r_c.pol);
	return lsa_io_r_close("", &r_c, rdata, 0);
}

/***************************************************************************
 api_lsa_create_secret
 ***************************************************************************/
static BOOL api_lsa_create_secret(prs_struct *data, prs_struct *rdata)
{
	LSA_R_CREATE_SECRET r_o;
	LSA_Q_CREATE_SECRET q_o;

	ZERO_STRUCT(q_o);
	ZERO_STRUCT(r_o);

	if (!lsa_io_q_create_secret("", &q_o, data, 0))
	{
		return False;
	}

	r_o.status = _lsa_create_secret(&q_o.pol,
					&q_o.uni_secret, q_o.des_access,
					&r_o.pol);
	return lsa_io_r_create_secret("", &r_o, rdata, 0);
}

/***************************************************************************
 api_lsa_set_secret.  AGH!  HACK! :)
 ***************************************************************************/
static BOOL api_lsa_set_secret(prs_struct *data, prs_struct *rdata)
{
	LSA_Q_SET_SECRET q_o;
	LSA_R_SET_SECRET r_o;
	STRING2 *val = NULL;

	ZERO_STRUCT(r_o);
	ZERO_STRUCT(q_o);

	if (!lsa_io_q_set_secret("", &q_o, data, 0))
	{
		return False;
	}

	if (q_o.value.ptr_secret)
		val = &q_o.value.enc_secret;

	r_o.status = _lsa_set_secret(&q_o.pol, val, q_o.unknown);

	return lsa_io_r_set_secret("", &r_o, rdata, 0);
}

/***************************************************************************
 api_lsa_query_secret.  AGH!  HACK! :)
 ***************************************************************************/
static BOOL api_lsa_query_secret(prs_struct *data, prs_struct *rdata)
{
	LSA_R_QUERY_SECRET r_o;
	LSA_Q_QUERY_SECRET q_o;
	NTTIME *curtim = NULL;
	NTTIME *oldtim = NULL;
	STRING2 *curval = NULL;
	STRING2 *oldval = NULL;

	ZERO_STRUCT(r_o);
	ZERO_STRUCT(q_o);

	if (!lsa_io_q_query_secret("", &q_o, data, 0))
	{
		return False;
	}

	/* HACK! */
	if (q_o.sec.curinfo.ptr_value != 0)
		curval = &q_o.sec.curinfo.value.enc_secret;
	if (q_o.sec.curinfo.ptr_update != 0)
		curtim = &q_o.sec.curinfo.last_update;
	if (q_o.sec.oldinfo.ptr_value != 0)
		oldval = &q_o.sec.oldinfo.value.enc_secret;
	if (q_o.sec.oldinfo.ptr_update != 0)
		oldtim = &q_o.sec.oldinfo.last_update;

	r_o.status = _lsa_query_secret(&q_o.pol,
				       curval, curtim, oldval, oldtim);

	memcpy(&r_o.sec, &q_o.sec, sizeof(r_o.sec));	/* urgh! HACK! */
	if (r_o.sec.curinfo.ptr_value != 0)	/* MORE HACK! */
	{
		r_o.sec.curinfo.value.ptr_secret = 1;
		make_strhdr2(&r_o.sec.curinfo.value.hdr_secret,
			     r_o.sec.curinfo.value.enc_secret.str_str_len,
			     r_o.sec.curinfo.value.enc_secret.str_max_len, 1);
	}
	if (r_o.sec.oldinfo.ptr_value != 0)	/* MORE HACK! */
	{
		r_o.sec.curinfo.value.ptr_secret = 1;
		make_strhdr2(&r_o.sec.oldinfo.value.hdr_secret,
			     r_o.sec.oldinfo.value.enc_secret.str_str_len,
			     r_o.sec.oldinfo.value.enc_secret.str_max_len, 1);
	}

	return lsa_io_r_query_secret("", &r_o, rdata, 0);
}

/***************************************************************************
 api_lsa_create_secret
 ***************************************************************************/
static BOOL api_lsa_open_secret(prs_struct *data, prs_struct *rdata)
{
	LSA_R_OPEN_SECRET r_o;
	LSA_Q_OPEN_SECRET q_o;

	ZERO_STRUCT(r_o);
	ZERO_STRUCT(q_o);

	if (!lsa_io_q_open_secret("", &q_o, data, 0))
	{
		return False;
	}

	r_o.status = _lsa_open_secret(&q_o.pol,
				      &q_o.uni_secret, q_o.des_access,
				      &r_o.pol);
	return lsa_io_r_open_secret("", &r_o, rdata, 0);
}

/***************************************************************************
 \PIPE\ntlsa commands
 ***************************************************************************/
static const struct api_struct api_lsa_cmds[] = {
	{"LSA_OPENPOLICY2", LSA_OPENPOLICY2, api_lsa_open_policy2},
	{"LSA_OPENPOLICY", LSA_OPENPOLICY, api_lsa_open_policy},
	{"LSA_QUERYINFOPOLICY", LSA_QUERYINFOPOLICY, api_lsa_query_info},
	{"LSA_ENUMTRUSTDOM", LSA_ENUMTRUSTDOM, api_lsa_enum_trust_dom},
	{"LSA_CLOSE", LSA_CLOSE, api_lsa_close},
	{"LSA_OPENSECRET", LSA_OPENSECRET, api_lsa_open_secret},
	{"LSA_CREATESECRET", LSA_CREATESECRET, api_lsa_create_secret},
	{"LSA_QUERYSECRET", LSA_QUERYSECRET, api_lsa_query_secret},
	{"LSA_SETSECRET", LSA_SETSECRET, api_lsa_set_secret},
	{"LSA_LOOKUPSIDS", LSA_LOOKUPSIDS, api_lsa_lookup_sids},
	{"LSA_LOOKUPNAMES", LSA_LOOKUPNAMES, api_lsa_lookup_names},
	{"LSA_SET_INFO", LSA_SET_INFO, api_lsa_set_info},
	{NULL, 0, NULL}
};

/***************************************************************************
 api_ntLsarpcTNP
 ***************************************************************************/
BOOL api_ntlsa_rpc(rpcsrv_struct * p)
{
	return api_rpcTNP(p, "api_ntlsa_rpc", api_lsa_cmds);
}
