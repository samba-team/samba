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
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/*******************************************************************
creates a LSA_TRANS_NAME structure.
********************************************************************/
BOOL make_lsa_trans_name(LSA_TRANS_NAME * trn, UNISTR2 * uni_name,
			 uint32 sid_name_use, char *name, uint32 idx)
{
	int len_name = strlen(name);

	trn->sid_name_use = sid_name_use;
	make_uni_hdr(&(trn->hdr_name), len_name);
	make_unistr2(uni_name, name, len_name);
	trn->domain_idx = idx;

	return True;
}

/*******************************************************************
reads or writes a LSA_TRANS_NAME structure.
********************************************************************/
static BOOL lsa_io_trans_name(char *desc, LSA_TRANS_NAME * trn,
			      prs_struct * ps, int depth)
{
	if (trn == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_trans_name");
	depth++;

	prs_align(ps);

	prs_uint32("sid_name_use", ps, depth, &(trn->sid_name_use));
	smb_io_unihdr("hdr_name", &(trn->hdr_name), ps, depth);
	prs_uint32("domain_idx  ", ps, depth, &(trn->domain_idx));

	return True;
}

/***************************************************************************
make_dom_ref - adds a domain if it's not already in, returns the index
 ***************************************************************************/
int make_dom_ref_uni(DOM_R_REF * ref, const UNISTR2 * uni_domname,
		     const DOM_SID * dom_sid)
{
	int num = 0;
	UNISTR2 uni_tmp;

	if (ref == NULL)
	{
		return -1;
	}

	if (uni_domname == NULL)
	{
		uni_domname = &uni_tmp;
		make_unistr2(&uni_tmp, NULL, 0);
	}

	for (num = 0; num < ref->num_ref_doms_1; num++)
	{
		if (unistr2equal(uni_domname,
				 &ref->ref_dom[num].uni_dom_name))
		{
			return num;
		}
	}

	if (num >= MAX_REF_DOMAINS)
	{
		/* index not found, already at maximum domain limit */
		return -1;
	}

	ref->num_ref_doms_1 = num + 1;
	ref->ptr_ref_dom = 1;
	ref->max_entries = MAX_REF_DOMAINS;
	ref->num_ref_doms_2 = num + 1;

	make_unihdr_from_unistr2(&(ref->hdr_ref_dom[num].hdr_dom_name),
				 uni_domname);
	copy_unistr2(&(ref->ref_dom[num].uni_dom_name), uni_domname);

	ref->hdr_ref_dom[num].ptr_dom_sid = dom_sid != NULL ? 1 : 0;
	make_dom_sid2(&(ref->ref_dom[num].ref_dom), dom_sid);

	return num;
}

int make_dom_ref(DOM_R_REF * ref, const char *domname,
		 const DOM_SID * dom_sid)
{
	UNISTR2 *uni_domname;
	int ret;

	uni_domname = unistr2_new(domname);
	ret = make_dom_ref_uni(ref, uni_domname, dom_sid);
	unistr2_free(uni_domname);
	return ret;
}

/*******************************************************************
reads or writes a DOM_R_REF structure.
********************************************************************/
static BOOL lsa_io_dom_r_ref(char *desc, DOM_R_REF * r_r, prs_struct * ps,
			     int depth)
{
	uint32 i, s, n;

	prs_debug(ps, depth, desc, "smb_io_dom_r_ref");
	depth++;

	if (r_r == NULL)
		return False;

	prs_align(ps);

	prs_uint32("num_ref_doms_1", ps, depth, &(r_r->num_ref_doms_1));	/* num referenced domains? */
	prs_uint32("ptr_ref_dom   ", ps, depth, &(r_r->ptr_ref_dom));	/* undocumented buffer pointer. */
	prs_uint32("max_entries   ", ps, depth, &(r_r->max_entries));	/* 32 - max number of entries */

	SMB_ASSERT_ARRAY(r_r->hdr_ref_dom, r_r->num_ref_doms_1);

	if (r_r->ptr_ref_dom != 0)
	{
		prs_uint32("num_ref_doms_2", ps, depth, &(r_r->num_ref_doms_2));	/* 4 - num referenced domains? */
		SMB_ASSERT_ARRAY(r_r->ref_dom, r_r->num_ref_doms_2);

		for (i = 0; i < r_r->num_ref_doms_1; i++)
		{
			fstring t;

			slprintf(t, sizeof(t) - 1, "dom_ref[%d] ", i);
			smb_io_unihdr(t, &(r_r->hdr_ref_dom[i].hdr_dom_name),
				      ps, depth);

			slprintf(t, sizeof(t) - 1, "sid_ptr[%d] ", i);
			prs_uint32(t, ps, depth,
				   &(r_r->hdr_ref_dom[i].ptr_dom_sid));
		}

		for (i = 0, n = 0, s = 0; i < r_r->num_ref_doms_2; i++)
		{
			fstring t;

			if (r_r->hdr_ref_dom[i].hdr_dom_name.buffer != 0)
			{
				slprintf(t, sizeof(t) - 1, "dom_ref[%d] ", i);
				smb_io_unistr2(t,
					       &(r_r->ref_dom[n].
						 uni_dom_name), True, ps, depth);	/* domain name unicode string */
				prs_align(ps);
				n++;
			}

			if (r_r->hdr_ref_dom[i].ptr_dom_sid != 0)
			{
				slprintf(t, sizeof(t) - 1, "sid_ptr[%d] ", i);
				smb_io_dom_sid2("",
						&(r_r->ref_dom[s].ref_dom),
						ps, depth);	/* referenced domain SIDs */
				s++;
			}
		}
	}

	return True;
}


/*******************************************************************
makes an LSA_SEC_QOS structure.
********************************************************************/
BOOL make_lsa_sec_qos(LSA_SEC_QOS * qos, uint16 imp_lev, uint8 ctxt,
		      uint8 eff, uint32 unknown)
{
	if (qos == NULL)
		return False;

	DEBUG(5, ("make_lsa_sec_qos\n"));

	qos->len = 0x0c;	/* length of quality of service block, in bytes */
	qos->sec_imp_level = imp_lev;
	qos->sec_ctxt_mode = ctxt;
	qos->effective_only = eff;
	qos->unknown = unknown;

	return True;
}

/*******************************************************************
reads or writes an LSA_SEC_QOS structure.
********************************************************************/
static BOOL lsa_io_sec_qos(char *desc, LSA_SEC_QOS * qos, prs_struct * ps,
			   int depth)
{
	int start;

	if (qos == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_obj_qos");
	depth++;

	prs_align(ps);

	start = ps->offset;

	/* these pointers had _better_ be zero, because we don't know
	   what they point to!
	 */
	prs_uint32("len           ", ps, depth, &(qos->len));	/* 0x18 - length (in bytes) inc. the length field. */
	prs_uint16("sec_imp_level ", ps, depth, &(qos->sec_imp_level));
	prs_uint8("sec_ctxt_mode ", ps, depth, &(qos->sec_ctxt_mode));
	prs_uint8("effective_only", ps, depth, &(qos->effective_only));
	prs_uint32("unknown       ", ps, depth, &(qos->unknown));

	if (qos->len != ps->offset - start)
	{
		DEBUG(3,
		      ("lsa_io_sec_qos: length %x does not match size %x\n",
		       qos->len, ps->offset - start));
	}

	return True;
}


/*******************************************************************
makes an LSA_OBJ_ATTR structure.
********************************************************************/
BOOL make_lsa_obj_attr(LSA_OBJ_ATTR * attr, uint32 attributes,
		       LSA_SEC_QOS * qos)
{
	if (attr == NULL)
		return False;

	DEBUG(5, ("make_lsa_obj_attr\n"));

	attr->len = 0x18;	/* length of object attribute block, in bytes */
	attr->ptr_root_dir = 0;
	attr->ptr_obj_name = 0;
	attr->attributes = attributes;
	attr->ptr_sec_desc = 0;

	if (qos != NULL)
	{
		attr->ptr_sec_qos = 1;
		attr->sec_qos = qos;
	}
	else
	{
		attr->ptr_sec_qos = 0;
		attr->sec_qos = NULL;
	}

	return True;
}

/*******************************************************************
reads or writes an LSA_OBJ_ATTR structure.
********************************************************************/
static BOOL lsa_io_obj_attr(char *desc, LSA_OBJ_ATTR * attr, prs_struct * ps,
			    int depth)
{
	int start;

	if (attr == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_obj_attr");
	depth++;

	prs_align(ps);

	start = ps->offset;

	/* these pointers had _better_ be zero, because we don't know
	   what they point to!
	 */
	prs_uint32("len         ", ps, depth, &(attr->len));	/* 0x18 - length (in bytes) inc. the length field. */
	prs_uint32("ptr_root_dir", ps, depth, &(attr->ptr_root_dir));	/* 0 - root directory (pointer) */
	prs_uint32("ptr_obj_name", ps, depth, &(attr->ptr_obj_name));	/* 0 - object name (pointer) */
	prs_uint32("attributes  ", ps, depth, &(attr->attributes));	/* 0 - attributes (undocumented) */
	prs_uint32("ptr_sec_desc", ps, depth, &(attr->ptr_sec_desc));	/* 0 - security descriptior (pointer) */
	prs_uint32("ptr_sec_qos ", ps, depth, &(attr->ptr_sec_qos));	/* security quality of service (pointer) */

	if (attr->len != ps->offset - start)
	{
		DEBUG(3,
		      ("lsa_io_obj_attr: length %x does not match size %x\n",
		       attr->len, ps->offset - start));
	}

	if (attr->ptr_sec_qos != 0 && attr->sec_qos != NULL)
	{
		lsa_io_sec_qos("sec_qos", attr->sec_qos, ps, depth);
	}

	return True;
}


/*******************************************************************
makes an LSA_Q_OPEN_POL structure.
********************************************************************/
BOOL make_q_open_pol(LSA_Q_OPEN_POL * r_q, uint16 system_name,
		     uint32 attributes,
		     uint32 desired_access, LSA_SEC_QOS * qos)
{
	if (r_q == NULL)
		return False;

	DEBUG(5,
	      ("make_open_pol: attr:%d da:%d\n", attributes, desired_access));

	r_q->ptr = 1;		/* undocumented pointer */

	if (qos == NULL)
	{
		r_q->des_access = desired_access;
	}

	r_q->system_name = system_name;
	make_lsa_obj_attr(&(r_q->attr), attributes, qos);

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_OPEN_POL structure.
********************************************************************/
BOOL lsa_io_q_open_pol(char *desc, LSA_Q_OPEN_POL * r_q, prs_struct * ps,
		       int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_open_pol");
	depth++;

	prs_uint32("ptr       ", ps, depth, &(r_q->ptr));
	prs_uint16("system_name", ps, depth, &(r_q->system_name));
	prs_align(ps);

	lsa_io_obj_attr("", &(r_q->attr), ps, depth);

	if (r_q->attr.ptr_sec_qos == 0)
	{
		prs_uint32("des_access", ps, depth, &(r_q->des_access));
	}

	return True;
}

/*******************************************************************
reads or writes an LSA_R_OPEN_POL structure.
********************************************************************/
BOOL lsa_io_r_open_pol(char *desc, LSA_R_OPEN_POL * r_p, prs_struct * ps,
		       int depth)
{
	if (r_p == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_open_pol");
	depth++;

	smb_io_pol_hnd("", &(r_p->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_p->status));

	return True;
}

/*******************************************************************
makes an LSA_Q_OPEN_POL2 structure.
********************************************************************/
BOOL make_q_open_pol2(LSA_Q_OPEN_POL2 * r_q, const char *server_name,
		      uint32 attributes,
		      uint32 desired_access, LSA_SEC_QOS * qos)
{
	if (r_q == NULL)
		return False;

	DEBUG(5,
	      ("make_open_pol2: attr:%d da:%d\n", attributes,
	       desired_access));

	r_q->ptr = 1;		/* undocumented pointer */

	if (qos == NULL)
	{
		r_q->des_access = desired_access;
	}

	make_unistr2(&(r_q->uni_server_name), server_name,
		     strlen(server_name));
	make_lsa_obj_attr(&(r_q->attr), attributes, qos);

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_OPEN_POL2 structure.
********************************************************************/
BOOL lsa_io_q_open_pol2(char *desc, LSA_Q_OPEN_POL2 * r_q, prs_struct * ps,
			int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_open_pol2");
	depth++;

	prs_uint32("ptr       ", ps, depth, &(r_q->ptr));

	smb_io_unistr2("", &(r_q->uni_server_name), r_q->ptr, ps, depth);
	prs_align(ps);

	lsa_io_obj_attr("", &(r_q->attr), ps, depth);

	if (r_q->attr.ptr_sec_qos == 0)
	{
		prs_uint32("des_access", ps, depth, &(r_q->des_access));
	}

	return True;
}

/*******************************************************************
reads or writes an LSA_R_OPEN_POL2 structure.
********************************************************************/
BOOL lsa_io_r_open_pol2(char *desc, LSA_R_OPEN_POL2 * r_p, prs_struct * ps,
			int depth)
{
	if (r_p == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_open_pol2");
	depth++;

	smb_io_pol_hnd("", &(r_p->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_p->status));

	return True;

	return True;
}

/*******************************************************************
makes an LSA_Q_QUERY_SEC_OBJ structure.
********************************************************************/
BOOL make_q_query_sec_obj(LSA_Q_QUERY_SEC_OBJ * q_q, const POLICY_HND *hnd,
				uint32 sec_info)
{
	if (q_q == NULL || hnd == NULL)
		return False;

	DEBUG(5, ("make_q_query_sec_obj\n"));

	q_q->pol = *hnd;
	q_q->sec_info = sec_info;

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_QUERY_SEC_OBJ structure.
********************************************************************/
BOOL lsa_io_q_query_sec_obj(char *desc, LSA_Q_QUERY_SEC_OBJ * q_q, prs_struct * ps,
		    int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_query_sec_obj");
	depth++;

	smb_io_pol_hnd("", &(q_q->pol), ps, depth);
	prs_uint32("sec_info", ps, depth, &(q_q->sec_info));

	return True;
}

/*******************************************************************
reads or writes a LSA_R_QUERY_SEC_OBJ structure.
********************************************************************/
BOOL lsa_io_r_query_sec_obj(char *desc,  LSA_R_QUERY_SEC_OBJ *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return False;

	prs_debug(ps, depth, desc, "lsa_io_r_query_sec_obj");
	depth++;

	prs_align(ps);

	prs_uint32("ptr", ps, depth, &(r_u->ptr));
	if (r_u->ptr != 0x0)
	{
		sec_io_desc_buf("sec", &r_u->buf, ps, depth);
	}
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}
/*******************************************************************
makes an LSA_Q_QUERY_INFO structure.
********************************************************************/
BOOL make_q_query(LSA_Q_QUERY_INFO * q_q, POLICY_HND *hnd, uint8 info_class)
{
	if (q_q == NULL || hnd == NULL)
		return False;

	DEBUG(5, ("make_q_query\n"));

	memcpy(&(q_q->pol), hnd, sizeof(q_q->pol));

	q_q->info_class = info_class;

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_QUERY_INFO structure.
********************************************************************/
BOOL lsa_io_q_query(char *desc, LSA_Q_QUERY_INFO * q_q, prs_struct * ps,
		    int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_query");
	depth++;

	smb_io_pol_hnd("", &(q_q->pol), ps, depth);

	prs_uint8("info_class", ps, depth, &q_q->info_class);
	prs_align(ps);

	return True;
}

/*******************************************************************
makes an LSA_Q_CREATE_SECRET structure.
********************************************************************/
BOOL make_q_create_secret(LSA_Q_CREATE_SECRET * q_o,
			  const POLICY_HND *pol_hnd, const char *secret_name,
			  uint32 desired_access)
{
	int len = strlen(secret_name);

	if (q_o == NULL)
		return False;

	DEBUG(5, ("make_q_create_secret"));

	memcpy(&(q_o->pol), pol_hnd, sizeof(q_o->pol));

	make_uni_hdr(&(q_o->hdr_secret), len);
	make_unistr2(&(q_o->uni_secret), secret_name, len);

	q_o->des_access = desired_access;

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_CREATE_SECRET structure.
********************************************************************/
BOOL lsa_io_q_create_secret(char *desc, LSA_Q_CREATE_SECRET * q_o,
			    prs_struct * ps, int depth)
{
	if (q_o == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_create_secret");
	depth++;

	smb_io_pol_hnd("", &(q_o->pol), ps, depth);

	prs_align(ps);
	smb_io_unihdr("", &(q_o->hdr_secret), ps, depth);
	smb_io_unistr2("", &(q_o->uni_secret), 1, ps, depth);

	prs_align(ps);
	prs_uint32("des_access", ps, depth, &(q_o->des_access));

	return True;
}

/*******************************************************************
reads or writes an LSA_R_CREATE_SECRET structure.
********************************************************************/
BOOL lsa_io_r_create_secret(char *desc, LSA_R_CREATE_SECRET * r_o,
			    prs_struct * ps, int depth)
{
	if (r_o == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_create_secret");
	depth++;

	smb_io_pol_hnd("", &(r_o->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_o->status));

	return True;
}

/*******************************************************************
makes an LSA_Q_OPEN_SECRET structure.
********************************************************************/
BOOL make_q_open_secret(LSA_Q_OPEN_SECRET * q_o, const POLICY_HND *pol_hnd,
			const char *secret_name, uint32 desired_access)
{
	int len = strlen(secret_name);

	if (q_o == NULL)
		return False;

	DEBUG(5, ("make_q_open_secret"));

	memcpy(&(q_o->pol), pol_hnd, sizeof(q_o->pol));

	make_uni_hdr(&(q_o->hdr_secret), len);
	make_unistr2(&(q_o->uni_secret), secret_name, len);

	q_o->des_access = desired_access;

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_OPEN_SECRET structure.
********************************************************************/
BOOL lsa_io_q_open_secret(char *desc, LSA_Q_OPEN_SECRET * q_o,
			  prs_struct * ps, int depth)
{
	if (q_o == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_open_secret");
	depth++;

	smb_io_pol_hnd("", &(q_o->pol), ps, depth);

	prs_align(ps);
	smb_io_unihdr("", &(q_o->hdr_secret), ps, depth);
	smb_io_unistr2("", &(q_o->uni_secret), 1, ps, depth);

	prs_align(ps);
	prs_uint32("des_access", ps, depth, &(q_o->des_access));

	return True;
}

/*******************************************************************
reads or writes an LSA_R_OPEN_SECRET structure.
********************************************************************/
BOOL lsa_io_r_open_secret(char *desc, LSA_R_OPEN_SECRET * r_o,
			  prs_struct * ps, int depth)
{
	if (r_o == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_open_secret");
	depth++;

	smb_io_pol_hnd("", &(r_o->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_o->status));

	return True;
}

/*******************************************************************
reads or writes an LSA_SECRET_VALUE structure.
********************************************************************/
BOOL lsa_io_secret_value(char *desc, LSA_SECRET_VALUE * value,
			 prs_struct * ps, int depth)
{
	if (value == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_secret_value");
	depth++;

	prs_align(ps);
	prs_uint32("ptr_secret", ps, depth, &(value->ptr_secret));

	if (value->ptr_secret != 0)
	{
		smb_io_strhdr2("hdr_secret", &(value->hdr_secret), ps, depth);
		smb_io_string2("secret", &(value->enc_secret),
			       value->hdr_secret.buffer, ps, depth);
	}

	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes an LSA_SECRET_INFO structure.
********************************************************************/
BOOL lsa_io_secret_info(char *desc, LSA_SECRET_INFO * info, prs_struct * ps,
			int depth)
{
	if (info == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_secret_info");
	depth++;

	prs_align(ps);
	prs_uint32("ptr_value ", ps, depth, &(info->ptr_value));

	if (info->ptr_value != 0)
	{
		lsa_io_secret_value("", &(info->value), ps, depth);
	}

	prs_align(ps);
	prs_uint32("ptr_update", ps, depth, &(info->ptr_update));

	if (info->ptr_update != 0)
	{
		ps->align = 8;
		prs_align(ps);
		ps->align = 4;

		smb_io_time("last_update", &(info->last_update), ps, depth);
	}

	prs_align(ps);

	return True;
}

/*******************************************************************
reads or writes an LSA_SECRET structure.
********************************************************************/
BOOL lsa_io_secret(char *desc, LSA_SECRET * q_q, prs_struct * ps, int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_secret");
	depth++;

	lsa_io_secret_info("", &(q_q->curinfo), ps, depth);
	lsa_io_secret_info("", &(q_q->oldinfo), ps, depth);

	return True;
}

/*******************************************************************
makes an LSA_Q_QUERY_SECRET structure.
********************************************************************/
BOOL make_q_query_secret(LSA_Q_QUERY_SECRET * q_q, POLICY_HND *pol,
			 const STRING2 *secret, const NTTIME * update)
{
	if (q_q == NULL)
		return False;

	DEBUG(5, ("make_q_query_secret\n"));

	memcpy(&(q_q->pol), pol, sizeof(q_q->pol));

	/* Want secret */
	q_q->sec.curinfo.ptr_value = secret != NULL ? 1 : 0;
	q_q->sec.curinfo.value.ptr_secret = 0;

	/* Want last change time */
	q_q->sec.curinfo.ptr_update = update != NULL ? 1 : 0;

	/* Don't care about old info */
	q_q->sec.oldinfo.ptr_value = 0;
	q_q->sec.oldinfo.ptr_update = 0;

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_QUERY_SECRET structure.
********************************************************************/
BOOL lsa_io_q_query_secret(char *desc, LSA_Q_QUERY_SECRET * q_q,
			   prs_struct * ps, int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_query_secret");
	depth++;

	smb_io_pol_hnd("", &(q_q->pol), ps, depth);
	lsa_io_secret("", &(q_q->sec), ps, depth);

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_QUERY_SECRET structure.
********************************************************************/
BOOL lsa_io_r_query_secret(char *desc, LSA_R_QUERY_SECRET * r_q,
			   prs_struct * ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_query_secret");
	depth++;

	lsa_io_secret("", &(r_q->sec), ps, depth);
	prs_align(ps);
	prs_uint32("status", ps, depth, &(r_q->status));

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_SET_SECRET structure.
********************************************************************/
BOOL lsa_io_q_set_secret(char *desc, LSA_Q_SET_SECRET * q_q, prs_struct * ps,
			 int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_set_secret");
	depth++;

	smb_io_pol_hnd("", &(q_q->pol), ps, depth);

	lsa_io_secret_value("", &(q_q->value), ps, depth);
	prs_uint32("unknown", ps, depth, &(q_q->unknown));

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_SET_SECRET structure.
********************************************************************/
BOOL lsa_io_r_set_secret(char *desc, LSA_R_SET_SECRET * r_q, prs_struct * ps,
			 int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_set_secret");
	depth++;

	prs_align(ps);
	prs_uint32("status", ps, depth, &(r_q->status));

	return True;
}

/*******************************************************************
makes an LSA_Q_ENUM_TRUST_DOM structure.
********************************************************************/
BOOL make_q_enum_trust_dom(LSA_Q_ENUM_TRUST_DOM * q_e,
			   POLICY_HND *pol,
			   uint32 enum_context, uint32 preferred_len)
{
	if (q_e == NULL)
		return False;

	DEBUG(5, ("make_q_enum_trust_dom\n"));

	memcpy(&(q_e->pol), pol, sizeof(q_e->pol));
	q_e->enum_context = enum_context;
	q_e->preferred_len = preferred_len;

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_ENUM_TRUST_DOM structure.
********************************************************************/
BOOL lsa_io_q_enum_trust_dom(char *desc, LSA_Q_ENUM_TRUST_DOM * q_e,
			     prs_struct * ps, int depth)
{
	if (q_e == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_enum_trust_dom");
	depth++;


	smb_io_pol_hnd("", &(q_e->pol), ps, depth);

	prs_uint32("enum_context ", ps, depth, &(q_e->enum_context));
	prs_uint32("preferred_len", ps, depth, &(q_e->preferred_len));

	return True;
}

/*******************************************************************
makes an LSA_R_ENUM_TRUST_DOM structure.
********************************************************************/
BOOL make_r_enum_trust_dom(LSA_R_ENUM_TRUST_DOM * r_e, int32 enum_context,
			   uint32 num_domains,
			   UNISTR2 * domain_names, DOM_SID ** domain_sids,
			   uint32 status)
{
	if (r_e == NULL)
		return False;

	DEBUG(5, ("make_r_enum_trust_dom\n"));

	r_e->enum_context = enum_context;

	if ((domain_names == NULL) || (domain_sids == NULL))
	{
		num_domains = 0;
	}

	if ((status == 0) && (num_domains != 0))
	{
		uint32 i;

		r_e->num_domains = num_domains;
		r_e->ptr_enum_domains = 1;
		r_e->num_domains2 = num_domains;

		r_e->hdr_domain_name = g_new(UNIHDR2, num_domains);
		r_e->domain_sid = g_new(DOM_SID2, num_domains);
		if ((r_e->hdr_domain_name == NULL)
		    || (r_e->domain_sid == NULL))
		{
			r_e->uni_domain_name = NULL;
			lsa_free_r_enum_trust_dom(r_e);
			r_e->status = status;
			return False;
		}
		r_e->uni_domain_name = domain_names;
		for (i = 0; i < num_domains; i++)
		{
			make_unihdr2_from_unistr2(&(r_e->hdr_domain_name[i]),
						  &(domain_names[i]));
			make_dom_sid2(&(r_e->domain_sid[i]), domain_sids[i]);
		}
	}
	else
	{
		r_e->num_domains = 0;
		r_e->ptr_enum_domains = 0;
	}

	r_e->status = status;

	return True;
}

/*******************************************************************
reads or writes an LSA_R_ENUM_TRUST_DOM structure.
********************************************************************/
BOOL lsa_io_r_enum_trust_dom(char *desc, LSA_R_ENUM_TRUST_DOM * r_e,
			     prs_struct * ps, int depth)
{
	if (r_e == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_enum_trust_dom");
	depth++;

	prs_uint32("enum_context    ", ps, depth, &(r_e->enum_context));
	prs_uint32("num_domains     ", ps, depth, &(r_e->num_domains));
	prs_uint32("ptr_enum_domains", ps, depth, &(r_e->ptr_enum_domains));

	if (r_e->ptr_enum_domains != 0)
	{
		uint32 i, num_domains;
		prs_uint32("num_domains2", ps, depth, &(r_e->num_domains2));
		num_domains = r_e->num_domains2;

		if (ps->io)
		{
			r_e->uni_domain_name = g_new(UNISTR2, num_domains);
			r_e->hdr_domain_name = g_new(UNIHDR2, num_domains);
			r_e->domain_sid = g_new(DOM_SID2, num_domains);
			if ((r_e->uni_domain_name == NULL)
			    || (r_e->hdr_domain_name == NULL)
			    || (r_e->domain_sid == NULL))
			{
				lsa_free_r_enum_trust_dom(r_e);
				return False;
			}
		}

		for (i = 0; i < num_domains; i++)
		{
			smb_io_unihdr2("", &(r_e->hdr_domain_name[i]), ps,
				       depth);
		}

		for (i = 0; i < num_domains; i++)
		{
			smb_io_unistr2("", &(r_e->uni_domain_name[i]),
				       r_e->hdr_domain_name[i].buffer, ps,
				       depth);
			prs_align(ps);
			smb_io_dom_sid2("", &(r_e->domain_sid[i]), ps, depth);
		}
	}

	prs_uint32("status", ps, depth, &(r_e->status));

	if (!ps->io)
	{
		r_e->uni_domain_name = NULL;
		lsa_free_r_enum_trust_dom(r_e);
	}

	return True;
}

void lsa_free_r_enum_trust_dom(LSA_R_ENUM_TRUST_DOM * r_e)
{
	if (r_e == NULL)
	{
		return;
	}
	safe_free(r_e->uni_domain_name);
	safe_free(r_e->hdr_domain_name);
	safe_free(r_e->domain_sid);
	r_e->uni_domain_name = NULL;
	r_e->hdr_domain_name = NULL;
	r_e->domain_sid = NULL;

	r_e->num_domains = 0;
	r_e->ptr_enum_domains = 0;
}

/*******************************************************************
reads or writes an LSA_R_QUERY_INFO structure.
********************************************************************/
BOOL lsa_io_r_query(char *desc, LSA_R_QUERY_INFO * r_q, prs_struct * ps,
		    int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_query");
	depth++;

	prs_uint32("undoc_buffer", ps, depth, &(r_q->undoc_buffer));

	if (r_q->undoc_buffer != 0)
	{
		prs_uint16("info_class", ps, depth, &(r_q->info_class));
		prs_align(ps);

		switch (r_q->info_class)
		{
			case 3:
			{
				smb_io_dom_query_3("", &(r_q->dom.id3), ps,
						   depth);
				break;
			}
			case 5:
			{
				smb_io_dom_query_5("", &(r_q->dom.id3), ps,
						   depth);
				break;
			}
			default:
			{
				/* PANIC! */
				break;
			}
		}
	}

	prs_uint32("status", ps, depth, &(r_q->status));

	return True;
}

/*******************************************************************
makes a LSA_SID_ENUM structure.
********************************************************************/
BOOL make_lsa_sid_enum(LSA_SID_ENUM * sen, uint32 num_entries,
		       DOM_SID ** sids)
{
	uint32 i, i2;
	if (sen == NULL || sids == NULL)
		return False;

	DEBUG(5, ("make_lsa_sid_enum\n"));

	sen->num_entries = num_entries;
	sen->ptr_sid_enum = num_entries != 0 ? 1 : 0;
	sen->num_entries2 = num_entries;

	SMB_ASSERT_ARRAY(sen->sid, sen->num_entries);

	for (i = 0, i2 = 0; i < num_entries; i++)
	{
		if (sids[i] != NULL)
		{
			sen->ptr_sid[i] = 1;
			make_dom_sid2(&(sen->sid[i2]), sids[i]);
			i2++;
		}
		else
		{
			sen->ptr_sid[i] = 0;
		}
	}

	return True;
}

/*******************************************************************
reads or writes a LSA_SID_ENUM structure.
********************************************************************/
static BOOL lsa_io_sid_enum(char *desc, LSA_SID_ENUM * sen,
			    prs_struct * ps, int depth)
{
	uint32 i;

	if (sen == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_sid_enum");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries ", ps, depth, &(sen->num_entries));
	prs_uint32("ptr_sid_enum", ps, depth, &(sen->ptr_sid_enum));
	prs_uint32("num_entries2", ps, depth, &(sen->num_entries2));

	SMB_ASSERT_ARRAY(sen->ptr_sid, sen->num_entries);

	for (i = 0; i < sen->num_entries; i++)
	{
		fstring temp;
		slprintf(temp, sizeof(temp) - 1, "ptr_sid[%d]", i);
		prs_uint32(temp, ps, depth, &(sen->ptr_sid[i]));	/* domain SID pointers to be looked up. */
	}

	SMB_ASSERT_ARRAY(sen->sid, sen->num_entries);

	for (i = 0; i < sen->num_entries; i++)
	{
		fstring temp;
		slprintf(temp, sizeof(temp) - 1, "sid[%d]", i);
		smb_io_dom_sid2(temp, &(sen->sid[i]), ps, depth);	/* domain SIDs to be looked up. */
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL lsa_io_trans_names(char *desc, LSA_TRANS_NAME_ENUM * trn,
			       prs_struct * ps, int depth)
{
	uint32 i;

	if (trn == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_trans_names");
	depth++;

	prs_align(ps);

	prs_uint32("num_entries    ", ps, depth, &(trn->num_entries));
	prs_uint32("ptr_trans_names", ps, depth, &(trn->ptr_trans_names));

	if (trn->ptr_trans_names != 0)
	{
		prs_uint32("num_entries2   ", ps, depth,
			   &(trn->num_entries2));
		SMB_ASSERT_ARRAY(trn->name, trn->num_entries);

		for (i = 0; i < trn->num_entries2; i++)
		{
			fstring t;
			slprintf(t, sizeof(t) - 1, "name[%d] ", i);

			lsa_io_trans_name(t, &(trn->name[i]), ps, depth);	/* translated name */

		}
		for (i = 0; i < trn->num_entries2; i++)
		{
			fstring t;
			slprintf(t, sizeof(t) - 1, "name[%d] ", i);

			smb_io_unistr2(t, &(trn->uni_name[i]),
				       trn->name[i].hdr_name.buffer, ps,
				       depth);
			prs_align(ps);
		}
	}

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_q_lookup_sids(LSA_Q_LOOKUP_SIDS * q_l, POLICY_HND *hnd,
			int num_sids, DOM_SID ** sids, uint16 level)
{
	if (q_l == NULL)
		return False;

	DEBUG(5, ("make_q_lookup_sids\n"));

	memcpy(&(q_l->pol), hnd, sizeof(q_l->pol));
	make_lsa_sid_enum(&(q_l->sids), num_sids, sids);

	q_l->names.ptr_trans_names = 0;
	q_l->names.num_entries = 0;

	q_l->level.value = level;

	return True;
}

/*******************************************************************
reads or writes a LSA_Q_LOOKUP_SIDS structure.
********************************************************************/
BOOL lsa_io_q_lookup_sids(char *desc, LSA_Q_LOOKUP_SIDS * q_s,
			  prs_struct * ps, int depth)
{
	if (q_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_lookup_sids");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("pol_hnd", &(q_s->pol), ps, depth);	/* policy handle */
	lsa_io_sid_enum("sids   ", &(q_s->sids), ps, depth);	/* sids to be looked up */
	lsa_io_trans_names("names  ", &(q_s->names), ps, depth);	/* translated names */
	smb_io_lookup_level("switch ", &(q_s->level), ps, depth);	/* lookup level */

	prs_uint32("mapped_count", ps, depth, &(q_s->mapped_count));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL lsa_io_r_lookup_sids(char *desc, LSA_R_LOOKUP_SIDS * r_s,
			  prs_struct * ps, int depth)
{
	if (r_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_lookup_sids");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_dom_ref", ps, depth, &(r_s->ptr_dom_ref));
	if (r_s->ptr_dom_ref != 0)
	{
		lsa_io_dom_r_ref("dom_ref", r_s->dom_ref, ps, depth);	/* domain reference info */
	}
	lsa_io_trans_names("names  ", r_s->names, ps, depth);	/* translated names */

	prs_align(ps);

	prs_uint32("mapped_count", ps, depth, &(r_s->mapped_count));

	prs_uint32("status      ", ps, depth, &(r_s->status));

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/
BOOL make_q_lookup_names(LSA_Q_LOOKUP_NAMES * q_l, POLICY_HND *hnd,
			 uint32 num_names, char **names)
{
	uint32 i;
	if (q_l == NULL)
		return False;

	DEBUG(5, ("make_q_lookup_names\n"));

	memcpy(&(q_l->pol), hnd, sizeof(q_l->pol));

	q_l->num_entries = num_names;
	q_l->num_entries2 = num_names;

	SMB_ASSERT_ARRAY(q_l->uni_name, q_l->num_entries);

	for (i = 0; i < num_names; i++)
	{
		const char *name = names[i];
		int len = strlen(name);
		make_uni_hdr(&q_l->hdr_name[i], len);
		make_unistr2(&q_l->uni_name[i], name, len);
	}

	q_l->num_trans_entries = 0;
	q_l->ptr_trans_sids = 0;
	q_l->lookup_level = 1;
	q_l->mapped_count = 0;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL lsa_io_q_lookup_names(char *desc, LSA_Q_LOOKUP_NAMES * q_r,
			   prs_struct * ps, int depth)
{
	uint32 i;

	if (q_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_lookup_names");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(q_r->pol), ps, depth);	/* policy handle */

	prs_uint32("num_entries    ", ps, depth, &(q_r->num_entries));
	prs_uint32("num_entries2   ", ps, depth, &(q_r->num_entries2));

	SMB_ASSERT_ARRAY(q_r->uni_name, q_r->num_entries);

	for (i = 0; i < q_r->num_entries; i++)
	{
		smb_io_unihdr("hdr_name", &(q_r->hdr_name[i]), ps, depth);	/* pointer names */
	}

	for (i = 0; i < q_r->num_entries; i++)
	{
		smb_io_unistr2("dom_name", &(q_r->uni_name[i]),
			       q_r->hdr_name[i].buffer, ps, depth);	/* names to be looked up */
		prs_align(ps);
	}

	prs_uint32("num_trans_entries ", ps, depth,
		   &(q_r->num_trans_entries));
	prs_uint32("ptr_trans_sids ", ps, depth, &(q_r->ptr_trans_sids));
	prs_uint32("lookup_level   ", ps, depth, &(q_r->lookup_level));
	prs_uint32("mapped_count   ", ps, depth, &(q_r->mapped_count));

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL lsa_io_r_lookup_names(char *desc, LSA_R_LOOKUP_NAMES * r_r,
			   prs_struct * ps, int depth)
{
	uint32 i;

	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_lookup_names");
	depth++;

	prs_align(ps);

	prs_uint32("ptr_dom_ref", ps, depth, &(r_r->ptr_dom_ref));
	if (r_r->ptr_dom_ref != 0)
	{
		lsa_io_dom_r_ref("", r_r->dom_ref, ps, depth);
	}

	prs_uint32("num_entries", ps, depth, &(r_r->num_entries));
	prs_uint32("ptr_entries", ps, depth, &(r_r->ptr_entries));

	if (r_r->ptr_entries != 0)
	{
		prs_uint32("num_entries2", ps, depth, &(r_r->num_entries2));

		if (r_r->num_entries2 != r_r->num_entries)
		{
			/* RPC fault */
			return False;
		}

		for (i = 0; i < r_r->num_entries2; i++)
		{
			smb_io_dom_rid2("", &(r_r->dom_rid[i]), ps, depth);	/* domain RIDs being looked up */
		}
	}

	prs_uint32("mapped_count", ps, depth, &(r_r->mapped_count));

	prs_uint32("status      ", ps, depth, &(r_r->status));

	return True;
}


/*******************************************************************
makes an LSA_Q_CLOSE structure.
********************************************************************/
BOOL make_lsa_q_close(LSA_Q_CLOSE * q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL)
		return False;

	DEBUG(5, ("make_lsa_q_close\n"));

	memcpy(&(q_c->pol), hnd, sizeof(q_c->pol));

	return True;
}

/*******************************************************************
reads or writes an LSA_Q_CLOSE structure.
********************************************************************/
BOOL lsa_io_q_close(char *desc, LSA_Q_CLOSE * q_c, prs_struct * ps, int depth)
{
	if (q_c == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_close");
	depth++;

	smb_io_pol_hnd("", &(q_c->pol), ps, depth);

	return True;
}

/*******************************************************************
reads or writes an LSA_R_CLOSE structure.
********************************************************************/
BOOL lsa_io_r_close(char *desc, LSA_R_CLOSE * r_c, prs_struct * ps, int depth)
{
	if (r_c == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_close");
	depth++;

	smb_io_pol_hnd("", &(r_c->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_c->status));

	return True;
}
