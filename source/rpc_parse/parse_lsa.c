/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
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

static BOOL lsa_io_trans_names(const char *desc, LSA_TRANS_NAME_ENUM *trn, prs_struct *ps, int depth);

/*******************************************************************
 Inits a LSA_TRANS_NAME structure.
********************************************************************/

void init_lsa_trans_name(LSA_TRANS_NAME *trn, UNISTR2 *uni_name,
			 uint16 sid_name_use, const char *name, uint32 idx)
{
	int len_name = strlen(name);

	if(len_name == 0)
		len_name = 1;

	trn->sid_name_use = sid_name_use;
	init_uni_hdr(&trn->hdr_name, len_name);
	init_unistr2(uni_name, name, len_name);
	trn->domain_idx = idx;
}

/*******************************************************************
 Reads or writes a LSA_TRANS_NAME structure.
********************************************************************/

static BOOL lsa_io_trans_name(const char *desc, LSA_TRANS_NAME *trn, prs_struct *ps, 
			      int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_trans_name");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint16("sid_name_use", ps, depth, &trn->sid_name_use))
		return False;
	if(!prs_align(ps))
		return False;
	
	if(!smb_io_unihdr ("hdr_name", &trn->hdr_name, ps, depth))
		return False;
	if(!prs_uint32("domain_idx  ", ps, depth, &trn->domain_idx))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a DOM_R_REF structure.
********************************************************************/

static BOOL lsa_io_dom_r_ref(const char *desc, DOM_R_REF *r_r, prs_struct *ps, 
			     int depth)
{
	int i;

	prs_debug(ps, depth, desc, "lsa_io_dom_r_ref");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("num_ref_doms_1", ps, depth, &r_r->num_ref_doms_1)) /* num referenced domains? */
		return False;
	if(!prs_uint32("ptr_ref_dom   ", ps, depth, &r_r->ptr_ref_dom)) /* undocumented buffer pointer. */
		return False;
	if(!prs_uint32("max_entries   ", ps, depth, &r_r->max_entries)) /* 32 - max number of entries */
		return False;

	SMB_ASSERT_ARRAY(r_r->hdr_ref_dom, r_r->num_ref_doms_1);

	if (r_r->ptr_ref_dom != 0) {

		if(!prs_uint32("num_ref_doms_2", ps, depth, &r_r->num_ref_doms_2)) /* 4 - num referenced domains? */
			return False;

		SMB_ASSERT_ARRAY(r_r->ref_dom, r_r->num_ref_doms_2);

		for (i = 0; i < r_r->num_ref_doms_1; i++) {
			fstring t;

			slprintf(t, sizeof(t) - 1, "dom_ref[%d] ", i);
			if(!smb_io_unihdr(t, &r_r->hdr_ref_dom[i].hdr_dom_name, ps, depth))
				return False;

			slprintf(t, sizeof(t) - 1, "sid_ptr[%d] ", i);
			if(!prs_uint32(t, ps, depth, &r_r->hdr_ref_dom[i].ptr_dom_sid))
				return False;
		}

		for (i = 0; i < r_r->num_ref_doms_2; i++) {
			fstring t;

			if (r_r->hdr_ref_dom[i].hdr_dom_name.buffer != 0) {
				slprintf(t, sizeof(t) - 1, "dom_ref[%d] ", i);
				if(!smb_io_unistr2(t, &r_r->ref_dom[i].uni_dom_name, True, ps, depth)) /* domain name unicode string */
					return False;
				if(!prs_align(ps))
					return False;
			}

			if (r_r->hdr_ref_dom[i].ptr_dom_sid != 0) {
				slprintf(t, sizeof(t) - 1, "sid_ptr[%d] ", i);
				if(!smb_io_dom_sid2(t, &r_r->ref_dom[i].ref_dom, ps, depth)) /* referenced domain SIDs */
					return False;
			}
		}
	}

	return True;
}

/*******************************************************************
 Inits an LSA_SEC_QOS structure.
********************************************************************/

void init_lsa_sec_qos(LSA_SEC_QOS *qos, uint16 imp_lev, uint8 ctxt, uint8 eff)
{
	DEBUG(5, ("init_lsa_sec_qos\n"));

	qos->len = 0x0c; /* length of quality of service block, in bytes */
	qos->sec_imp_level = imp_lev;
	qos->sec_ctxt_mode = ctxt;
	qos->effective_only = eff;
}

/*******************************************************************
 Reads or writes an LSA_SEC_QOS structure.
********************************************************************/

static BOOL lsa_io_sec_qos(const char *desc,  LSA_SEC_QOS *qos, prs_struct *ps, 
			   int depth)
{
	uint32 start;

	prs_debug(ps, depth, desc, "lsa_io_obj_qos");
	depth++;

	if(!prs_align(ps))
		return False;
	
	start = prs_offset(ps);

	/* these pointers had _better_ be zero, because we don't know
	   what they point to!
	 */
	if(!prs_uint32("len           ", ps, depth, &qos->len)) /* 0x18 - length (in bytes) inc. the length field. */
		return False;
	if(!prs_uint16("sec_imp_level ", ps, depth, &qos->sec_imp_level ))
		return False;
	if(!prs_uint8 ("sec_ctxt_mode ", ps, depth, &qos->sec_ctxt_mode ))
		return False;
	if(!prs_uint8 ("effective_only", ps, depth, &qos->effective_only))
		return False;

	if (qos->len != prs_offset(ps) - start) {
		DEBUG(3,("lsa_io_sec_qos: length %x does not match size %x\n",
		         qos->len, prs_offset(ps) - start));
	}

	return True;
}

/*******************************************************************
 Inits an LSA_OBJ_ATTR structure.
********************************************************************/

void init_lsa_obj_attr(LSA_OBJ_ATTR *attr, uint32 attributes, LSA_SEC_QOS *qos)
{
	DEBUG(5, ("init_lsa_obj_attr\n"));

	attr->len = 0x18; /* length of object attribute block, in bytes */
	attr->ptr_root_dir = 0;
	attr->ptr_obj_name = 0;
	attr->attributes = attributes;
	attr->ptr_sec_desc = 0;
	
	if (qos != NULL) {
		attr->ptr_sec_qos = 1;
		attr->sec_qos = qos;
	} else {
		attr->ptr_sec_qos = 0;
		attr->sec_qos = NULL;
	}
}

/*******************************************************************
 Reads or writes an LSA_OBJ_ATTR structure.
********************************************************************/

static BOOL lsa_io_obj_attr(const char *desc, LSA_OBJ_ATTR *attr, prs_struct *ps, 
			    int depth)
{
	uint32 start;

	prs_debug(ps, depth, desc, "lsa_io_obj_attr");
	depth++;

	if(!prs_align(ps))
		return False;
	
	start = prs_offset(ps);

	/* these pointers had _better_ be zero, because we don't know
	   what they point to!
	 */
	if(!prs_uint32("len         ", ps, depth, &attr->len)) /* 0x18 - length (in bytes) inc. the length field. */
		return False;
	if(!prs_uint32("ptr_root_dir", ps, depth, &attr->ptr_root_dir)) /* 0 - root directory (pointer) */
		return False;
	if(!prs_uint32("ptr_obj_name", ps, depth, &attr->ptr_obj_name)) /* 0 - object name (pointer) */
		return False;
	if(!prs_uint32("attributes  ", ps, depth, &attr->attributes)) /* 0 - attributes (undocumented) */
		return False;
	if(!prs_uint32("ptr_sec_desc", ps, depth, &attr->ptr_sec_desc)) /* 0 - security descriptior (pointer) */
		return False;
	if(!prs_uint32("ptr_sec_qos ", ps, depth, &attr->ptr_sec_qos )) /* security quality of service (pointer) */
		return False;

	/* code commented out as it's not necessary true (tested with hyena). JFM, 11/22/2001 */
#if 0
	if (attr->len != prs_offset(ps) - start) {
		DEBUG(3,("lsa_io_obj_attr: length %x does not match size %x\n",
		         attr->len, prs_offset(ps) - start));
		return False;
	}
#endif

	if (attr->ptr_sec_qos != 0) {
		if (UNMARSHALLING(ps))
			if (!(attr->sec_qos = (LSA_SEC_QOS *)prs_alloc_mem(ps,sizeof(LSA_SEC_QOS))))
				return False;

		if(!lsa_io_sec_qos("sec_qos", attr->sec_qos, ps, depth))
			return False;
	}

	return True;
}


/*******************************************************************
 Inits an LSA_Q_OPEN_POL structure.
********************************************************************/

void init_q_open_pol(LSA_Q_OPEN_POL *r_q, uint16 system_name,
		     uint32 attributes, uint32 desired_access,
		     LSA_SEC_QOS *qos)
{
	DEBUG(5, ("init_open_pol: attr:%d da:%d\n", attributes, 
		  desired_access));

	r_q->ptr = 1; /* undocumented pointer */

	r_q->des_access = desired_access;

	r_q->system_name = system_name;
	init_lsa_obj_attr(&r_q->attr, attributes, qos);
}

/*******************************************************************
 Reads or writes an LSA_Q_OPEN_POL structure.
********************************************************************/

BOOL lsa_io_q_open_pol(const char *desc, LSA_Q_OPEN_POL *r_q, prs_struct *ps, 
		       int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_open_pol");
	depth++;

	if(!prs_uint32("ptr       ", ps, depth, &r_q->ptr))
		return False;
	if(!prs_uint16("system_name", ps, depth, &r_q->system_name))
		return False;
	if(!prs_align( ps ))
		return False;

	if(!lsa_io_obj_attr("", &r_q->attr, ps, depth))
		return False;

	if(!prs_uint32("des_access", ps, depth, &r_q->des_access))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_OPEN_POL structure.
********************************************************************/

BOOL lsa_io_r_open_pol(const char *desc, LSA_R_OPEN_POL *r_p, prs_struct *ps, 
		       int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_open_pol");
	depth++;

	if(!smb_io_pol_hnd("", &r_p->pol, ps, depth))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_p->status))
		return False;

	return True;
}

/*******************************************************************
 Inits an LSA_Q_OPEN_POL2 structure.
********************************************************************/

void init_q_open_pol2(LSA_Q_OPEN_POL2 *r_q, const char *server_name,
			uint32 attributes, uint32 desired_access,
			LSA_SEC_QOS *qos)
{
	DEBUG(5, ("init_q_open_pol2: attr:%d da:%d\n", attributes, 
		  desired_access));

	r_q->ptr = 1; /* undocumented pointer */

	r_q->des_access = desired_access;

	init_unistr2(&r_q->uni_server_name, server_name, 
		     strlen(server_name) + 1);

	init_lsa_obj_attr(&r_q->attr, attributes, qos);
}

/*******************************************************************
 Reads or writes an LSA_Q_OPEN_POL2 structure.
********************************************************************/

BOOL lsa_io_q_open_pol2(const char *desc, LSA_Q_OPEN_POL2 *r_q, prs_struct *ps, 
			int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_open_pol2");
	depth++;

	if(!prs_uint32("ptr       ", ps, depth, &r_q->ptr))
		return False;

	if(!smb_io_unistr2 ("", &r_q->uni_server_name, r_q->ptr, ps, depth))
		return False;
	if(!lsa_io_obj_attr("", &r_q->attr, ps, depth))
		return False;

	if(!prs_uint32("des_access", ps, depth, &r_q->des_access))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_OPEN_POL2 structure.
********************************************************************/

BOOL lsa_io_r_open_pol2(const char *desc, LSA_R_OPEN_POL2 *r_p, prs_struct *ps, 
			int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_open_pol2");
	depth++;

	if(!smb_io_pol_hnd("", &r_p->pol, ps, depth))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_p->status))
		return False;

	return True;
}

/*******************************************************************
makes an LSA_Q_QUERY_SEC_OBJ structure.
********************************************************************/

void init_q_query_sec_obj(LSA_Q_QUERY_SEC_OBJ *q_q, const POLICY_HND *hnd, 
			  uint32 sec_info)
{
	DEBUG(5, ("init_q_query_sec_obj\n"));

	q_q->pol = *hnd;
	q_q->sec_info = sec_info;

	return;
}

/*******************************************************************
 Reads or writes an LSA_Q_QUERY_SEC_OBJ structure.
********************************************************************/

BOOL lsa_io_q_query_sec_obj(const char *desc, LSA_Q_QUERY_SEC_OBJ *q_q, 
			    prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_query_sec_obj");
	depth++;

	if (!smb_io_pol_hnd("", &q_q->pol, ps, depth))
		return False;

	if (!prs_uint32("sec_info", ps, depth, &q_q->sec_info))
		return False;

	return True;
} 

/*******************************************************************
 Reads or writes a LSA_R_QUERY_SEC_OBJ structure.
********************************************************************/

BOOL lsa_io_r_query_sec_obj(const char *desc, LSA_R_QUERY_SEC_OBJ *r_u, 
			    prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_query_sec_obj");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("ptr", ps, depth, &r_u->ptr))
		return False;

	if (r_u->ptr != 0) {
		if (!sec_io_desc_buf("sec", &r_u->buf, ps, depth))
			return False;
	}

	if (!prs_ntstatus("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
 Inits an LSA_Q_QUERY_INFO structure.
********************************************************************/

void init_q_query(LSA_Q_QUERY_INFO *q_q, POLICY_HND *hnd, uint16 info_class)
{
	DEBUG(5, ("init_q_query\n"));

	memcpy(&q_q->pol, hnd, sizeof(q_q->pol));

	q_q->info_class = info_class;
}

/*******************************************************************
 Reads or writes an LSA_Q_QUERY_INFO structure.
********************************************************************/

BOOL lsa_io_q_query(const char *desc, LSA_Q_QUERY_INFO *q_q, prs_struct *ps, 
		    int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_query");
	depth++;

	if(!smb_io_pol_hnd("", &q_q->pol, ps, depth))
		return False;

	if(!prs_uint16("info_class", ps, depth, &q_q->info_class))
		return False;

	return True;
}

/*******************************************************************
makes an LSA_Q_ENUM_TRUST_DOM structure.
********************************************************************/
BOOL init_q_enum_trust_dom(LSA_Q_ENUM_TRUST_DOM * q_e, POLICY_HND *pol,
			   uint32 enum_context, uint32 preferred_len)
{
	DEBUG(5, ("init_q_enum_trust_dom\n"));

	q_e->pol = *pol;
	q_e->enum_context = enum_context;
	q_e->preferred_len = preferred_len;

	return True;
}

/*******************************************************************
 Reads or writes an LSA_Q_ENUM_TRUST_DOM structure.
********************************************************************/

BOOL lsa_io_q_enum_trust_dom(const char *desc, LSA_Q_ENUM_TRUST_DOM *q_e, 
			     prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_enum_trust_dom");
	depth++;

	if(!smb_io_pol_hnd("", &q_e->pol, ps, depth))
		return False;

	if(!prs_uint32("enum_context ", ps, depth, &q_e->enum_context))
		return False;
	if(!prs_uint32("preferred_len", ps, depth, &q_e->preferred_len))
		return False;

	return True;
}

/*******************************************************************
 Inits an LSA_R_ENUM_TRUST_DOM structure.
********************************************************************/

void init_r_enum_trust_dom(TALLOC_CTX *ctx, LSA_R_ENUM_TRUST_DOM *r_e, uint32 enum_context, 
			   const char *domain_name, DOM_SID *domain_sid,
                           NTSTATUS status)
{
        DEBUG(5, ("init_r_enum_trust_dom\n"));
	
        r_e->enum_context = enum_context;
	
        if (NT_STATUS_IS_OK(status)) {
                int len_domain_name = strlen(domain_name) + 1;
		
                r_e->num_domains  = 1;
                r_e->ptr_enum_domains = 1;
                r_e->num_domains2 = 1;
		
		if (!(r_e->hdr_domain_name = (UNIHDR2 *)talloc(ctx,sizeof(UNIHDR2))))
			return;

		if (!(r_e->uni_domain_name = (UNISTR2 *)talloc(ctx,sizeof(UNISTR2))))
			return;

		if (!(r_e->domain_sid = (DOM_SID2 *)talloc(ctx,sizeof(DOM_SID2))))
			return;

		init_uni_hdr2(&r_e->hdr_domain_name[0], len_domain_name);
		init_unistr2 (&r_e->uni_domain_name[0], domain_name, 
			      len_domain_name);
		init_dom_sid2(&r_e->domain_sid[0], domain_sid);
        } else {
                r_e->num_domains = 0;
                r_e->ptr_enum_domains = 0;
        }
	
        r_e->status = status;
}

/*******************************************************************
 Reads or writes an LSA_R_ENUM_TRUST_DOM structure.
********************************************************************/

BOOL lsa_io_r_enum_trust_dom(const char *desc, LSA_R_ENUM_TRUST_DOM *r_e, 
			     prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_enum_trust_dom");
	depth++;

	if(!prs_uint32("enum_context    ", ps, depth, &r_e->enum_context))
		return False;
	if(!prs_uint32("num_domains     ", ps, depth, &r_e->num_domains))
		return False;
	if(!prs_uint32("ptr_enum_domains", ps, depth, &r_e->ptr_enum_domains))
		return False;

	if (r_e->ptr_enum_domains) {
		int i, num_domains;

		if(!prs_uint32("num_domains2", ps, depth, &r_e->num_domains2))
			return False;

		num_domains = r_e->num_domains2;

		if (UNMARSHALLING(ps)) {
			if (!(r_e->hdr_domain_name = (UNIHDR2 *)prs_alloc_mem(ps,sizeof(UNIHDR2) * num_domains)))
				return False;

			if (!(r_e->uni_domain_name = (UNISTR2 *)prs_alloc_mem(ps,sizeof(UNISTR2) * num_domains)))
				return False;

			if (!(r_e->domain_sid = (DOM_SID2 *)prs_alloc_mem(ps,sizeof(DOM_SID2) * num_domains)))
				return False;
		}

		for (i = 0; i < num_domains; i++) {
			if(!smb_io_unihdr2 ("", &r_e->hdr_domain_name[i], ps, 
					    depth))
				return False;
		}
		
		for (i = 0; i < num_domains; i++) {
			if(!smb_io_unistr2 ("", &r_e->uni_domain_name[i],
					    r_e->hdr_domain_name[i].buffer, 
					    ps, depth))
				return False;
			if(!smb_io_dom_sid2("", &r_e->domain_sid[i], ps, 
					    depth))
				return False;
		}
	}

	if(!prs_ntstatus("status", ps, depth, &r_e->status))
		return False;

	return True;
}

/*******************************************************************
reads or writes a dom query structure.
********************************************************************/

static BOOL lsa_io_dom_query(const char *desc, DOM_QUERY *d_q, prs_struct *ps, int depth)
{
	if (d_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_dom_query");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint16("uni_dom_max_len", ps, depth, &d_q->uni_dom_max_len)) /* domain name string length * 2 */
		return False;
	if(!prs_uint16("uni_dom_str_len", ps, depth, &d_q->uni_dom_str_len)) /* domain name string length * 2 */
		return False;

	if(!prs_uint32("buffer_dom_name", ps, depth, &d_q->buffer_dom_name)) /* undocumented domain name string buffer pointer */
		return False;
	if(!prs_uint32("buffer_dom_sid ", ps, depth, &d_q->buffer_dom_sid)) /* undocumented domain SID string buffer pointer */
		return False;

	if(!smb_io_unistr2("unistr2", &d_q->uni_domain_name, d_q->buffer_dom_name, ps, depth)) /* domain name (unicode string) */
		return False;

	if(!prs_align(ps))
		return False;

	if (d_q->buffer_dom_sid != 0) {
		if(!smb_io_dom_sid2("", &d_q->dom_sid, ps, depth)) /* domain SID */
			return False;
	} else {
		memset((char *)&d_q->dom_sid, '\0', sizeof(d_q->dom_sid));
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

static BOOL lsa_io_dom_query_2(const char *desc, DOM_QUERY_2 *d_q, prs_struct *ps, int depth)
{
	uint32 ptr = 1;

	if (d_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_dom_query_2");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("auditing_enabled", ps, depth, &d_q->auditing_enabled))
		return False;
	if (!prs_uint32("ptr   ", ps, depth, &ptr))
		return False;
	if (!prs_uint32("count1", ps, depth, &d_q->count1))
		return False;
	if (!prs_uint32("count2", ps, depth, &d_q->count2))
		return False;

	if (UNMARSHALLING(ps)) {
		d_q->auditsettings = (uint32 *)talloc_zero(ps->mem_ctx, d_q->count2 * sizeof(uint32));
	}

	if (d_q->auditsettings == NULL) {
		DEBUG(1, ("lsa_io_dom_query_2: NULL auditsettings!\n"));
		return False;
	}

	if (!prs_uint32s(False, "auditsettings", ps, depth, d_q->auditsettings, d_q->count2))
		return False;

    return True;
}

/*******************************************************************
 Reads or writes a dom query structure.
********************************************************************/

static BOOL lsa_io_dom_query_3(const char *desc, DOM_QUERY_3 *d_q, prs_struct *ps, int depth)
{
	return lsa_io_dom_query("", d_q, ps, depth);
}

/*******************************************************************
 Reads or writes a dom query structure.
********************************************************************/

BOOL lsa_io_dom_query_5(const char *desc, DOM_QUERY_5 *d_q, prs_struct *ps, int depth)
{
	return lsa_io_dom_query("", d_q, ps, depth);
}

/*******************************************************************
 Reads or writes a dom query structure.
********************************************************************/

static BOOL lsa_io_dom_query_6(const char *desc, DOM_QUERY_6 *d_q, prs_struct *ps, int depth)
{
	if (d_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_dom_query_6");
	depth++;

	if (!prs_uint16("server_role", ps, depth, &d_q->server_role))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_QUERY_INFO structure.
********************************************************************/

BOOL lsa_io_r_query(const char *desc, LSA_R_QUERY_INFO *r_q, prs_struct *ps,
		    int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_query");
	depth++;

	if(!prs_uint32("undoc_buffer", ps, depth, &r_q->undoc_buffer))
		return False;

	if (r_q->undoc_buffer != 0) {
		if(!prs_uint16("info_class", ps, depth, &r_q->info_class))
			return False;

		if(!prs_align(ps))
			return False;

		switch (r_q->info_class) {
		case 2:
			if(!lsa_io_dom_query_2("", &r_q->dom.id2, ps, depth))
				return False;
			break;
		case 3:
			if(!lsa_io_dom_query_3("", &r_q->dom.id3, ps, depth))
				return False;
			break;
		case 5:
			if(!lsa_io_dom_query_5("", &r_q->dom.id5, ps, depth))
				return False;
			break;
		case 6:
			if(!lsa_io_dom_query_6("", &r_q->dom.id6, ps, depth))
				return False;
			break;
		default:
			/* PANIC! */
			break;
		}
	}

	if(!prs_align(ps))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_q->status))
		return False;

	return True;
}

/*******************************************************************
 Inits a LSA_SID_ENUM structure.
********************************************************************/

void init_lsa_sid_enum(TALLOC_CTX *mem_ctx, LSA_SID_ENUM *sen, 
		       int num_entries, DOM_SID *sids)
{
	int i;

	DEBUG(5, ("init_lsa_sid_enum\n"));

	sen->num_entries  = num_entries;
	sen->ptr_sid_enum = (num_entries != 0);
	sen->num_entries2 = num_entries;

	/* Allocate memory for sids and sid pointers */

	if (num_entries == 0) return;

	if ((sen->ptr_sid = (uint32 *)talloc_zero(mem_ctx, num_entries * 
					     sizeof(uint32))) == NULL) {
		DEBUG(3, ("init_lsa_sid_enum(): out of memory for ptr_sid\n"));
		return;
	}

	if ((sen->sid = (DOM_SID2 *)talloc_zero(mem_ctx, num_entries * 
					   sizeof(DOM_SID2))) == NULL) {
		DEBUG(3, ("init_lsa_sid_enum(): out of memory for sids\n"));
		return;
	}

	/* Copy across SIDs and SID pointers */

	for (i = 0; i < num_entries; i++) {
		sen->ptr_sid[i] = 1;
		init_dom_sid2(&sen->sid[i], &sids[i]);
	}
}

/*******************************************************************
 Reads or writes a LSA_SID_ENUM structure.
********************************************************************/

static BOOL lsa_io_sid_enum(const char *desc, LSA_SID_ENUM *sen, prs_struct *ps, 
			    int depth)
{
	int i;

	prs_debug(ps, depth, desc, "lsa_io_sid_enum");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("num_entries ", ps, depth, &sen->num_entries))
		return False;
	if(!prs_uint32("ptr_sid_enum", ps, depth, &sen->ptr_sid_enum))
		return False;

	/*
	   if the ptr is NULL, leave here. checked from a real w2k trace.
	   JFM, 11/23/2001
	 */
	
	if (sen->ptr_sid_enum==0)
		return True;

	if(!prs_uint32("num_entries2", ps, depth, &sen->num_entries2))
		return False;

	/* Mallocate memory if we're unpacking from the wire */

	if (UNMARSHALLING(ps)) {
		if ((sen->ptr_sid = (uint32 *)prs_alloc_mem( ps,
			sen->num_entries * sizeof(uint32))) == NULL) {
			DEBUG(3, ("init_lsa_sid_enum(): out of memory for "
				  "ptr_sid\n"));
			return False;
		}

		if ((sen->sid = (DOM_SID2 *)prs_alloc_mem( ps,
			sen->num_entries * sizeof(DOM_SID2))) == NULL) {
			DEBUG(3, ("init_lsa_sid_enum(): out of memory for "
				  "sids\n"));
			return False;
		}
	}

	for (i = 0; i < sen->num_entries; i++) {	
		fstring temp;

		slprintf(temp, sizeof(temp) - 1, "ptr_sid[%d]", i);
		if(!prs_uint32(temp, ps, depth, &sen->ptr_sid[i])) {
			return False;
		}
	}

	for (i = 0; i < sen->num_entries; i++) {
		fstring temp;

		slprintf(temp, sizeof(temp) - 1, "sid[%d]", i);
		if(!smb_io_dom_sid2(temp, &sen->sid[i], ps, depth)) {
			return False;
		}
	}

	return True;
}

/*******************************************************************
 Inits an LSA_R_ENUM_TRUST_DOM structure.
********************************************************************/

void init_q_lookup_sids(TALLOC_CTX *mem_ctx, LSA_Q_LOOKUP_SIDS *q_l, 
			POLICY_HND *hnd, int num_sids, DOM_SID *sids,
			uint16 level)
{
	DEBUG(5, ("init_r_enum_trust_dom\n"));

	ZERO_STRUCTP(q_l);

	memcpy(&q_l->pol, hnd, sizeof(q_l->pol));
	init_lsa_sid_enum(mem_ctx, &q_l->sids, num_sids, sids);
	
	q_l->level.value = level;
}

/*******************************************************************
 Reads or writes a LSA_Q_LOOKUP_SIDS structure.
********************************************************************/

BOOL lsa_io_q_lookup_sids(const char *desc, LSA_Q_LOOKUP_SIDS *q_s, prs_struct *ps,
			  int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_lookup_sids");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("pol_hnd", &q_s->pol, ps, depth)) /* policy handle */
		return False;
	if(!lsa_io_sid_enum("sids   ", &q_s->sids, ps, depth)) /* sids to be looked up */
		return False;
	if(!lsa_io_trans_names("names  ", &q_s->names, ps, depth)) /* translated names */
		return False;
	if(!smb_io_lookup_level("switch ", &q_s->level, ps, depth)) /* lookup level */
		return False;

	if(!prs_uint32("mapped_count", ps, depth, &q_s->mapped_count))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static BOOL lsa_io_trans_names(const char *desc, LSA_TRANS_NAME_ENUM *trn,
                prs_struct *ps, int depth)
{
	int i;

	prs_debug(ps, depth, desc, "lsa_io_trans_names");
	depth++;

	if(!prs_align(ps))
		return False;
   
	if(!prs_uint32("num_entries    ", ps, depth, &trn->num_entries))
		return False;
	if(!prs_uint32("ptr_trans_names", ps, depth, &trn->ptr_trans_names))
		return False;

	if (trn->ptr_trans_names != 0) {
		if(!prs_uint32("num_entries2   ", ps, depth, 
			       &trn->num_entries2))
			return False;

		if (UNMARSHALLING(ps)) {
			if ((trn->name = (LSA_TRANS_NAME *)
			     prs_alloc_mem(ps, trn->num_entries * 
				    sizeof(LSA_TRANS_NAME))) == NULL) {
				return False;
			}

			if ((trn->uni_name = (UNISTR2 *)
			     prs_alloc_mem(ps, trn->num_entries *
				    sizeof(UNISTR2))) == NULL) {
				return False;
			}
		}

		for (i = 0; i < trn->num_entries2; i++) {
			fstring t;
			slprintf(t, sizeof(t) - 1, "name[%d] ", i);

			if(!lsa_io_trans_name(t, &trn->name[i], ps, depth)) /* translated name */
				return False;
		}

		for (i = 0; i < trn->num_entries2; i++) {
			fstring t;
			slprintf(t, sizeof(t) - 1, "name[%d] ", i);

			if(!smb_io_unistr2(t, &trn->uni_name[i], trn->name[i].hdr_name.buffer, ps, depth))
				return False;
			if(!prs_align(ps))
				return False;
		}
	}

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

BOOL lsa_io_r_lookup_sids(const char *desc, LSA_R_LOOKUP_SIDS *r_s, 
			  prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_lookup_sids");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_dom_ref", ps, depth, &r_s->ptr_dom_ref))
		return False;

	if (r_s->ptr_dom_ref != 0)
		if(!lsa_io_dom_r_ref ("dom_ref", r_s->dom_ref, ps, depth)) /* domain reference info */
			return False;

	if(!lsa_io_trans_names("names  ", r_s->names, ps, depth)) /* translated names */
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("mapped_count", ps, depth, &r_s->mapped_count))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &r_s->status))
		return False;

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/

void init_q_lookup_names(TALLOC_CTX *mem_ctx, LSA_Q_LOOKUP_NAMES *q_l, 
			 POLICY_HND *hnd, int num_names, const char **names)
{
	int i;

	DEBUG(5, ("init_q_lookup_names\n"));

	ZERO_STRUCTP(q_l);

	q_l->pol = *hnd;
	q_l->num_entries = num_names;
	q_l->num_entries2 = num_names;
	q_l->lookup_level = 1;

	if ((q_l->uni_name = (UNISTR2 *)talloc_zero(
		mem_ctx, num_names * sizeof(UNISTR2))) == NULL) {
		DEBUG(3, ("init_q_lookup_names(): out of memory\n"));
		return;
	}

	if ((q_l->hdr_name = (UNIHDR *)talloc_zero(
		mem_ctx, num_names * sizeof(UNIHDR))) == NULL) {
		DEBUG(3, ("init_q_lookup_names(): out of memory\n"));
		return;
	}

	for (i = 0; i < num_names; i++) {
		int len;
		len = strlen(unix_to_dos_static(names[i]));

		init_uni_hdr(&q_l->hdr_name[i], len);
		init_unistr2(&q_l->uni_name[i], unix_to_dos_static(names[i]), len);
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL lsa_io_q_lookup_names(const char *desc, LSA_Q_LOOKUP_NAMES *q_r, 
			   prs_struct *ps, int depth)
{
	int i;

	prs_debug(ps, depth, desc, "lsa_io_q_lookup_names");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("", &q_r->pol, ps, depth)) /* policy handle */
		return False;

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_entries    ", ps, depth, &q_r->num_entries))
		return False;
	if(!prs_uint32("num_entries2   ", ps, depth, &q_r->num_entries2))
		return False;

	if (UNMARSHALLING(ps)) {
		if (q_r->num_entries) {
			if ((q_r->hdr_name = (UNIHDR *)prs_alloc_mem(ps,
					q_r->num_entries * sizeof(UNIHDR))) == NULL)
				return False;
			if ((q_r->uni_name = (UNISTR2 *)prs_alloc_mem(ps,
					q_r->num_entries * sizeof(UNISTR2))) == NULL)
				return False;
		}
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unihdr("hdr_name", &q_r->hdr_name[i], ps, depth)) /* pointer names */
			return False;
	}

	for (i = 0; i < q_r->num_entries; i++) {
		if(!prs_align(ps))
			return False;
		if(!smb_io_unistr2("dom_name", &q_r->uni_name[i], q_r->hdr_name[i].buffer, ps, depth)) /* names to be looked up */
			return False;
	}

	if(!prs_align(ps))
		return False;
	if(!prs_uint32("num_trans_entries ", ps, depth, &q_r->num_trans_entries))
		return False;
	if(!prs_uint32("ptr_trans_sids ", ps, depth, &q_r->ptr_trans_sids))
		return False;
	if(!prs_uint32("lookup_level   ", ps, depth, &q_r->lookup_level))
		return False;
	if(!prs_uint32("mapped_count   ", ps, depth, &q_r->mapped_count))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL lsa_io_r_lookup_names(const char *desc, LSA_R_LOOKUP_NAMES *r_r, 
			   prs_struct *ps, int depth)
{
	int i;

	prs_debug(ps, depth, desc, "lsa_io_r_lookup_names");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_dom_ref", ps, depth, &r_r->ptr_dom_ref))
		return False;

	if (r_r->ptr_dom_ref != 0)
		if(!lsa_io_dom_r_ref("", r_r->dom_ref, ps, depth))
			return False;

	if(!prs_uint32("num_entries", ps, depth, &r_r->num_entries))
		return False;
	if(!prs_uint32("ptr_entries", ps, depth, &r_r->ptr_entries))
		return False;

	if (r_r->ptr_entries != 0) {
		if(!prs_uint32("num_entries2", ps, depth, &r_r->num_entries2))
			return False;

		if (r_r->num_entries2 != r_r->num_entries) {
			/* RPC fault */
			return False;
		}

		if (UNMARSHALLING(ps)) {
			if ((r_r->dom_rid = (DOM_RID2 *)prs_alloc_mem(ps, r_r->num_entries2 * sizeof(DOM_RID2)))
			    == NULL) {
				DEBUG(3, ("lsa_io_r_lookup_names(): out of memory\n"));
				return False;
			}
		}

		for (i = 0; i < r_r->num_entries2; i++)
			if(!smb_io_dom_rid2("", &r_r->dom_rid[i], ps, depth)) /* domain RIDs being looked up */
				return False;
	}

	if(!prs_uint32("mapped_count", ps, depth, &r_r->mapped_count))
		return False;

	if(!prs_ntstatus("status      ", ps, depth, &r_r->status))
		return False;

	return True;
}


/*******************************************************************
 Inits an LSA_Q_CLOSE structure.
********************************************************************/

void init_lsa_q_close(LSA_Q_CLOSE *q_c, POLICY_HND *hnd)
{
	DEBUG(5, ("init_lsa_q_close\n"));

	memcpy(&q_c->pol, hnd, sizeof(q_c->pol));
}

/*******************************************************************
 Reads or writes an LSA_Q_CLOSE structure.
********************************************************************/

BOOL lsa_io_q_close(const char *desc, LSA_Q_CLOSE *q_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_close");
	depth++;

	if(!smb_io_pol_hnd("", &q_c->pol, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_CLOSE structure.
********************************************************************/

BOOL lsa_io_r_close(const char *desc,  LSA_R_CLOSE *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_close");
	depth++;

	if(!smb_io_pol_hnd("", &r_c->pol, ps, depth))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LSA_Q_OPEN_SECRET structure.
********************************************************************/

BOOL lsa_io_q_open_secret(const char *desc, LSA_Q_OPEN_SECRET *q_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_open_secret");
	depth++;

	/* Don't bother to read or write at present... */
	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_OPEN_SECRET structure.
********************************************************************/

BOOL lsa_io_r_open_secret(const char *desc, LSA_R_OPEN_SECRET *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_open_secret");
	depth++;

	if(!prs_align(ps))
		return False;
   
	if(!prs_uint32("dummy1", ps, depth, &r_c->dummy1))
		return False;
	if(!prs_uint32("dummy2", ps, depth, &r_c->dummy2))
		return False;
	if(!prs_uint32("dummy3", ps, depth, &r_c->dummy3))
		return False;
	if(!prs_uint32("dummy4", ps, depth, &r_c->dummy4))
		return False;
	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}

/*******************************************************************
 Inits an LSA_Q_ENUM_PRIVS structure.
********************************************************************/

void init_q_enum_privs(LSA_Q_ENUM_PRIVS *q_q, POLICY_HND *hnd, uint32 enum_context, uint32 pref_max_length)
{
	DEBUG(5, ("init_q_enum_privs\n"));

	memcpy(&q_q->pol, hnd, sizeof(q_q->pol));

	q_q->enum_context = enum_context;
	q_q->pref_max_length = pref_max_length;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL lsa_io_q_enum_privs(const char *desc, LSA_Q_ENUM_PRIVS *q_q, prs_struct *ps, int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_enum_privs");
	depth++;

	if (!smb_io_pol_hnd("", &q_q->pol, ps, depth))
		return False;

	if(!prs_uint32("enum_context   ", ps, depth, &q_q->enum_context))
		return False;
	if(!prs_uint32("pref_max_length", ps, depth, &q_q->pref_max_length))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
static BOOL lsa_io_priv_entries(const char *desc, LSA_PRIV_ENTRY *entries, uint32 count, prs_struct *ps, int depth)
{
	uint32 i;

	if (entries == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_priv_entries");
	depth++;

	if(!prs_align(ps))
		return False;

	for (i = 0; i < count; i++) {
		if (!smb_io_unihdr("", &entries[i].hdr_name, ps, depth))
			return False;
		if(!prs_uint32("luid_low ", ps, depth, &entries[i].luid_low))
			return False;
		if(!prs_uint32("luid_high", ps, depth, &entries[i].luid_high))
			return False;
	}

	for (i = 0; i < count; i++)
		if (!smb_io_unistr2("", &entries[i].name, entries[i].hdr_name.buffer, ps, depth))
			return False;

	return True;
}

/*******************************************************************
 Inits an LSA_R_ENUM_PRIVS structure.
********************************************************************/

void init_lsa_r_enum_privs(LSA_R_ENUM_PRIVS *r_u, uint32 enum_context,
			  uint32 count, LSA_PRIV_ENTRY *entries)
{
	DEBUG(5, ("init_lsa_r_enum_privs\n"));

	r_u->enum_context=enum_context;
	r_u->count=count;
	
	if (entries!=NULL) {
		r_u->ptr=1;
		r_u->count1=count;
		r_u->privs=entries;
	} else {
		r_u->ptr=0;
		r_u->count1=0;
		r_u->privs=NULL;
	}		
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL lsa_io_r_enum_privs(const char *desc, LSA_R_ENUM_PRIVS *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_enum_privs");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("enum_context", ps, depth, &r_q->enum_context))
		return False;
	if(!prs_uint32("count", ps, depth, &r_q->count))
		return False;
	if(!prs_uint32("ptr", ps, depth, &r_q->ptr))
		return False;

	if (r_q->ptr) {
		if(!prs_uint32("count1", ps, depth, &r_q->count1))
			return False;

		if (UNMARSHALLING(ps))
			if (!(r_q->privs = (LSA_PRIV_ENTRY *)prs_alloc_mem(ps, sizeof(LSA_PRIV_ENTRY) * r_q->count1)))
				return False;

		if (!lsa_io_priv_entries("", r_q->privs, r_q->count1, ps, depth))
			return False;
	}

	if(!prs_align(ps))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_q->status))
		return False;

	return True;
}

void init_lsa_priv_get_dispname(LSA_Q_PRIV_GET_DISPNAME *trn, POLICY_HND *hnd, const char *name, uint16 lang_id, uint16 lang_id_sys)
{
	int len_name = strlen(name);

	if(len_name == 0)
		len_name = 1;

	memcpy(&trn->pol, hnd, sizeof(trn->pol));

	init_uni_hdr(&trn->hdr_name, len_name);
	init_unistr2(&trn->name, name, len_name);
	trn->lang_id = lang_id;
	trn->lang_id_sys = lang_id_sys;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL lsa_io_q_priv_get_dispname(const char *desc, LSA_Q_PRIV_GET_DISPNAME *q_q, prs_struct *ps, int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_priv_get_dispname");
	depth++;

	if(!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("", &q_q->pol, ps, depth))
		return False;

	if (!smb_io_unihdr("hdr_name", &q_q->hdr_name, ps, depth))
		return False;

	if (!smb_io_unistr2("name", &q_q->name, q_q->hdr_name.buffer, ps, depth))
		return False;

	if(!prs_uint16("lang_id    ", ps, depth, &q_q->lang_id))
		return False;
	if(!prs_uint16("lang_id_sys", ps, depth, &q_q->lang_id_sys))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL lsa_io_r_priv_get_dispname(const char *desc, LSA_R_PRIV_GET_DISPNAME *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_priv_get_dispname");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("ptr_info", ps, depth, &r_q->ptr_info))
		return False;

	if (r_q->ptr_info){
		if (!smb_io_unihdr("hdr_name", &r_q->hdr_desc, ps, depth))
			return False;

		if (!smb_io_unistr2("desc", &r_q->desc, r_q->hdr_desc.buffer, ps, depth))
			return False;
	}
/*
	if(!prs_align(ps))
		return False;
*/
	if(!prs_uint16("lang_id", ps, depth, &r_q->lang_id))
		return False;

	if(!prs_align(ps))
		return False;
	if(!prs_ntstatus("status", ps, depth, &r_q->status))
		return False;

	return True;
}

void init_lsa_q_enum_accounts(LSA_Q_ENUM_ACCOUNTS *trn, POLICY_HND *hnd, uint32 enum_context, uint32 pref_max_length)
{
	memcpy(&trn->pol, hnd, sizeof(trn->pol));

	trn->enum_context = enum_context;
	trn->pref_max_length = pref_max_length;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL lsa_io_q_enum_accounts(const char *desc, LSA_Q_ENUM_ACCOUNTS *q_q, prs_struct *ps, int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_q_enum_accounts");
	depth++;

	if (!smb_io_pol_hnd("", &q_q->pol, ps, depth))
		return False;

	if(!prs_uint32("enum_context   ", ps, depth, &q_q->enum_context))
		return False;
	if(!prs_uint32("pref_max_length", ps, depth, &q_q->pref_max_length))
		return False;

	return True;
}

/*******************************************************************
 Inits an LSA_R_ENUM_PRIVS structure.
********************************************************************/

void init_lsa_r_enum_accounts(LSA_R_ENUM_ACCOUNTS *r_u, uint32 enum_context)
{
	DEBUG(5, ("init_lsa_r_enum_accounts\n"));

	r_u->enum_context=enum_context;
	if (r_u->enum_context!=0) {
		r_u->sids.num_entries=enum_context;
		r_u->sids.ptr_sid_enum=1;
		r_u->sids.num_entries2=enum_context;
	} else {
		r_u->sids.num_entries=0;
		r_u->sids.ptr_sid_enum=0;
		r_u->sids.num_entries2=0;
	}
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL lsa_io_r_enum_accounts(const char *desc, LSA_R_ENUM_ACCOUNTS *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "lsa_io_r_enum_accounts");
	depth++;

	if (!prs_align(ps))
		return False;

	if(!prs_uint32("enum_context", ps, depth, &r_q->enum_context))
		return False;

	if (!lsa_io_sid_enum("sids", &r_q->sids, ps, depth))
		return False;

	if (!prs_align(ps))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_q->status))
		return False;

	return True;
}


/*******************************************************************
 Reads or writes an LSA_Q_UNK_GET_CONNUSER structure.
********************************************************************/

BOOL lsa_io_q_unk_get_connuser(const char *desc, LSA_Q_UNK_GET_CONNUSER *q_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_unk_get_connuser");
	depth++;

	if(!prs_align(ps))
		return False;
   
	if(!prs_uint32("ptr_srvname", ps, depth, &q_c->ptr_srvname))
		return False;

	if(!smb_io_unistr2("uni2_srvname", &q_c->uni2_srvname, q_c->ptr_srvname, ps, depth)) /* server name to be looked up */
		return False;

	if (!prs_align(ps))
	  return False;

	if(!prs_uint32("unk1", ps, depth, &q_c->unk1))
		return False;
	if(!prs_uint32("unk2", ps, depth, &q_c->unk2))
		return False;
	if(!prs_uint32("unk3", ps, depth, &q_c->unk3))
		return False;

	/* Don't bother to read or write at present... */
	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_UNK_GET_CONNUSER structure.
********************************************************************/

BOOL lsa_io_r_unk_get_connuser(const char *desc, LSA_R_UNK_GET_CONNUSER *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_unk_get_connuser");
	depth++;

	if(!prs_align(ps))
		return False;
   
	if(!prs_uint32("ptr_user_name", ps, depth, &r_c->ptr_user_name))
		return False;
	if(!smb_io_unihdr("hdr_user_name", &r_c->hdr_user_name, ps, depth))
		return False;
	if(!smb_io_unistr2("uni2_user_name", &r_c->uni2_user_name, r_c->ptr_user_name, ps, depth))
		return False;

	if (!prs_align(ps))
	  return False;
	
	if(!prs_uint32("unk1", ps, depth, &r_c->unk1))
		return False;

	if(!prs_uint32("ptr_dom_name", ps, depth, &r_c->ptr_dom_name))
		return False;
	if(!smb_io_unihdr("hdr_dom_name", &r_c->hdr_dom_name, ps, depth))
		return False;
	if(!smb_io_unistr2("uni2_dom_name", &r_c->uni2_dom_name, r_c->ptr_dom_name, ps, depth))
		return False;

	if (!prs_align(ps))
	  return False;
	
	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}

void init_lsa_q_open_account(LSA_Q_OPENACCOUNT *trn, POLICY_HND *hnd, DOM_SID *sid, uint32 desired_access)
{
	memcpy(&trn->pol, hnd, sizeof(trn->pol));

	init_dom_sid2(&trn->sid, sid);
	trn->access = desired_access;
}

/*******************************************************************
 Reads or writes an LSA_Q_OPENACCOUNT structure.
********************************************************************/

BOOL lsa_io_q_open_account(const char *desc, LSA_Q_OPENACCOUNT *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_open_account");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!smb_io_pol_hnd("pol", &r_c->pol, ps, depth))
		return False;

	if(!smb_io_dom_sid2("sid", &r_c->sid, ps, depth)) /* domain SID */
		return False;

 	if(!prs_uint32("access", ps, depth, &r_c->access))
		return False;
  
	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_OPENACCOUNT structure.
********************************************************************/

BOOL lsa_io_r_open_account(const char *desc, LSA_R_OPENACCOUNT  *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_open_account");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!smb_io_pol_hnd("pol", &r_c->pol, ps, depth))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}


void init_lsa_q_enum_privsaccount(LSA_Q_ENUMPRIVSACCOUNT *trn, POLICY_HND *hnd)
{
	memcpy(&trn->pol, hnd, sizeof(trn->pol));

}

/*******************************************************************
 Reads or writes an LSA_Q_ENUMPRIVSACCOUNT structure.
********************************************************************/

BOOL lsa_io_q_enum_privsaccount(const char *desc, LSA_Q_ENUMPRIVSACCOUNT *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_enum_privsaccount");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!smb_io_pol_hnd("pol", &r_c->pol, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LUID structure.
********************************************************************/

BOOL lsa_io_luid(const char *desc, LUID *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_luid");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!prs_uint32("low", ps, depth, &r_c->low))
		return False;

	if(!prs_uint32("high", ps, depth, &r_c->high))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LUID_ATTR structure.
********************************************************************/

BOOL lsa_io_luid_attr(const char *desc, LUID_ATTR *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_luid_attr");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if (!lsa_io_luid(desc, &r_c->luid, ps, depth))
		return False;

	if(!prs_uint32("attr", ps, depth, &r_c->attr))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an PRIVILEGE_SET structure.
********************************************************************/

BOOL lsa_io_privilege_set(const char *desc, PRIVILEGE_SET *r_c, prs_struct *ps, int depth)
{
	uint32 i;

	prs_debug(ps, depth, desc, "lsa_io_privilege_set");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!prs_uint32("count", ps, depth, &r_c->count))
		return False;
	if(!prs_uint32("control", ps, depth, &r_c->control))
		return False;

	for (i=0; i<r_c->count; i++) {
		if (!lsa_io_luid_attr(desc, &r_c->set[i], ps, depth))
			return False;
	}
	
	return True;
}

void init_lsa_r_enum_privsaccount(LSA_R_ENUMPRIVSACCOUNT *r_u, LUID_ATTR *set, uint32 count, uint32 control)
{
	r_u->ptr=1;
	r_u->count=count;
	r_u->set.set=set;
	r_u->set.count=count;
	r_u->set.control=control;
	DEBUG(10,("init_lsa_r_enum_privsaccount: %d %d privileges\n", r_u->count, r_u->set.count));
}

/*******************************************************************
 Reads or writes an LSA_R_ENUMPRIVSACCOUNT structure.
********************************************************************/

BOOL lsa_io_r_enum_privsaccount(const char *desc, LSA_R_ENUMPRIVSACCOUNT *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_enum_privsaccount");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!prs_uint32("ptr", ps, depth, &r_c->ptr))
		return False;

	if (r_c->ptr!=0) {
		if(!prs_uint32("count", ps, depth, &r_c->count))
			return False;

		/* malloc memory if unmarshalling here */

		if (UNMARSHALLING(ps) && r_c->count!=0) {
			if (!(r_c->set.set = (LUID_ATTR *)prs_alloc_mem(ps,sizeof(LUID_ATTR) * r_c->count)))
				return False;

		}
		
		if(!lsa_io_privilege_set(desc, &r_c->set, ps, depth))
			return False;
	}

	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}



/*******************************************************************
 Reads or writes an  LSA_Q_GETSYSTEMACCOUNTstructure.
********************************************************************/

BOOL lsa_io_q_getsystemaccount(const char *desc, LSA_Q_GETSYSTEMACCOUNT  *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_getsystemaccount");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!smb_io_pol_hnd("pol", &r_c->pol, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an  LSA_R_GETSYSTEMACCOUNTstructure.
********************************************************************/

BOOL lsa_io_r_getsystemaccount(const char *desc, LSA_R_GETSYSTEMACCOUNT  *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_getsystemaccount");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!prs_uint32("access", ps, depth, &r_c->access))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}


/*******************************************************************
 Reads or writes an LSA_Q_SETSYSTEMACCOUNT structure.
********************************************************************/

BOOL lsa_io_q_setsystemaccount(const char *desc, LSA_Q_SETSYSTEMACCOUNT  *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_setsystemaccount");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!smb_io_pol_hnd("pol", &r_c->pol, ps, depth))
		return False;

	if(!prs_uint32("access", ps, depth, &r_c->access))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_SETSYSTEMACCOUNT structure.
********************************************************************/

BOOL lsa_io_r_setsystemaccount(const char *desc, LSA_R_SETSYSTEMACCOUNT  *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_setsystemaccount");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}


void init_lsa_q_lookupprivvalue(LSA_Q_LOOKUPPRIVVALUE *trn, POLICY_HND *hnd, const char *name)
{
	int len_name = strlen(name);
	memcpy(&trn->pol, hnd, sizeof(trn->pol));

	if(len_name == 0)
		len_name = 1;

	init_uni_hdr(&trn->hdr_right, len_name);
	init_unistr2(&trn->uni2_right, name, len_name);
}

/*******************************************************************
 Reads or writes an LSA_Q_LOOKUPPRIVVALUE  structure.
********************************************************************/

BOOL lsa_io_q_lookupprivvalue(const char *desc, LSA_Q_LOOKUPPRIVVALUE  *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_lookupprivvalue");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!smb_io_pol_hnd("pol", &r_c->pol, ps, depth))
		return False;
	if(!smb_io_unihdr ("hdr_name", &r_c->hdr_right, ps, depth))
		return False;
	if(!smb_io_unistr2("uni2_right", &r_c->uni2_right, r_c->hdr_right.buffer, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an  LSA_R_LOOKUPPRIVVALUE structure.
********************************************************************/

BOOL lsa_io_r_lookupprivvalue(const char *desc, LSA_R_LOOKUPPRIVVALUE  *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_lookupprivvalue");
	depth++;

	if(!prs_align(ps))
		return False;
		
	if(!lsa_io_luid("luid", &r_c->luid, ps, depth))
		return False;
 
	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}


/*******************************************************************
 Reads or writes an LSA_Q_ADDPRIVS structure.
********************************************************************/

BOOL lsa_io_q_addprivs(const char *desc, LSA_Q_ADDPRIVS *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_addprivs");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!smb_io_pol_hnd("pol", &r_c->pol, ps, depth))
		return False;
	
	if(!prs_uint32("count", ps, depth, &r_c->count))
		return False;

	if (UNMARSHALLING(ps) && r_c->count!=0) {
		if (!(r_c->set.set = (LUID_ATTR *)prs_alloc_mem(ps,sizeof(LUID_ATTR) * r_c->count)))
			return False;
	}
	
	if(!lsa_io_privilege_set(desc, &r_c->set, ps, depth))
		return False;
	
	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_ADDPRIVS structure.
********************************************************************/

BOOL lsa_io_r_addprivs(const char *desc, LSA_R_ADDPRIVS *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_addprivs");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes an LSA_Q_REMOVEPRIVS structure.
********************************************************************/

BOOL lsa_io_q_removeprivs(const char *desc, LSA_Q_REMOVEPRIVS *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_q_removeprivs");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!smb_io_pol_hnd("pol", &r_c->pol, ps, depth))
		return False;
	
	if(!prs_uint32("allrights", ps, depth, &r_c->allrights))
		return False;

	if(!prs_uint32("ptr", ps, depth, &r_c->ptr))
		return False;

	/* 
	 * JFM: I'm not sure at all if the count is inside the ptr
	 * never seen one with ptr=0
	 */

	if (r_c->ptr!=0) {
		if(!prs_uint32("count", ps, depth, &r_c->count))
			return False;

		if (UNMARSHALLING(ps) && r_c->count!=0) {
			if (!(r_c->set.set = (LUID_ATTR *)prs_alloc_mem(ps,sizeof(LUID_ATTR) * r_c->count)))
				return False;
		}

		if(!lsa_io_privilege_set(desc, &r_c->set, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
 Reads or writes an LSA_R_REMOVEPRIVS structure.
********************************************************************/

BOOL lsa_io_r_removeprivs(const char *desc, LSA_R_REMOVEPRIVS *r_c, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "lsa_io_r_removeprivs");
	depth++;

	if(!prs_align(ps))
		return False;
 
	if(!prs_ntstatus("status", ps, depth, &r_c->status))
		return False;

	return True;
}

BOOL policy_handle_is_valid(const POLICY_HND *hnd)
{
	POLICY_HND zero_pol;

	ZERO_STRUCT(zero_pol);
	return ((memcmp(&zero_pol, hnd, sizeof(POLICY_HND)) == 0) ? False : True );
}
