/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
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
#include "nterr.h"

extern int DEBUGLEVEL;

/*******************************************************************
makes an LSA_SEC_QOS structure.
********************************************************************/
void make_lsa_sec_qos(LSA_SEC_QOS *qos, uint16 imp_lev, uint8 ctxt, uint8 eff,
				uint32 unknown)
{
	if (qos == NULL) return;

	DEBUG(5,("make_lsa_sec_qos\n"));

	qos->len = 0x0c; /* length of quality of service block, in bytes */
	qos->sec_imp_level = imp_lev;
	qos->sec_ctxt_mode = ctxt;
	qos->effective_only = eff;
	qos->unknown = unknown;
}

/*******************************************************************
reads or writes an LSA_SEC_QOS structure.
********************************************************************/
static void lsa_io_sec_qos(char *desc,  LSA_SEC_QOS *qos, prs_struct *ps, int depth)
{
	int start;

	if (qos == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_obj_qos");
	depth++;

	prs_align(ps);
	
	start = ps->offset;

	/* these pointers had _better_ be zero, because we don't know
	   what they point to!
	 */
	prs_uint32("len           ", ps, depth, &(qos->len           )); /* 0x18 - length (in bytes) inc. the length field. */
	prs_uint16("sec_imp_level ", ps, depth, &(qos->sec_imp_level )); 
	prs_uint8 ("sec_ctxt_mode ", ps, depth, &(qos->sec_ctxt_mode )); 
	prs_uint8 ("effective_only", ps, depth, &(qos->effective_only)); 
	prs_uint32("unknown       ", ps, depth, &(qos->unknown       )); 

	if (qos->len != ps->offset - start)
	{
		DEBUG(3,("lsa_io_sec_qos: length %x does not match size %x\n",
		         qos->len, ps->offset - start));
	}
}


/*******************************************************************
makes an LSA_OBJ_ATTR structure.
********************************************************************/
void make_lsa_obj_attr(LSA_OBJ_ATTR *attr, uint32 attributes, LSA_SEC_QOS *qos)
{
	if (attr == NULL) return;

	DEBUG(5,("make_lsa_obj_attr\n"));

	attr->len = 0x18; /* length of object attribute block, in bytes */
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
}

/*******************************************************************
reads or writes an LSA_OBJ_ATTR structure.
********************************************************************/
static void lsa_io_obj_attr(char *desc,  LSA_OBJ_ATTR *attr, prs_struct *ps, int depth)
{
	int start;

	if (attr == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_obj_attr");
	depth++;

	prs_align(ps);
	
	start = ps->offset;

	/* these pointers had _better_ be zero, because we don't know
	   what they point to!
	 */
	prs_uint32("len         ", ps, depth, &(attr->len         )); /* 0x18 - length (in bytes) inc. the length field. */
	prs_uint32("ptr_root_dir", ps, depth, &(attr->ptr_root_dir)); /* 0 - root directory (pointer) */
	prs_uint32("ptr_obj_name", ps, depth, &(attr->ptr_obj_name)); /* 0 - object name (pointer) */
	prs_uint32("attributes  ", ps, depth, &(attr->attributes  )); /* 0 - attributes (undocumented) */
	prs_uint32("ptr_sec_desc", ps, depth, &(attr->ptr_sec_desc)); /* 0 - security descriptior (pointer) */
	prs_uint32("ptr_sec_qos ", ps, depth, &(attr->ptr_sec_qos )); /* security quality of service (pointer) */

	if (attr->len != ps->offset - start)
	{
		DEBUG(3,("lsa_io_obj_attr: length %x does not match size %x\n",
		         attr->len, ps->offset - start));
	}

	if (attr->ptr_sec_qos != 0 && attr->sec_qos != NULL)
	{
		lsa_io_sec_qos("sec_qos", attr->sec_qos, ps, depth);
	}
}


/*******************************************************************
makes an LSA_Q_OPEN_POL structure.
********************************************************************/
void make_q_open_pol(LSA_Q_OPEN_POL *r_q, uint16 system_name,
			uint32 attributes,
			uint32 desired_access,
			LSA_SEC_QOS *qos)
{
	if (r_q == NULL) return;

	DEBUG(5,("make_open_pol: attr:%d da:%d\n", attributes, desired_access));

	r_q->ptr = 1; /* undocumented pointer */

	if (qos == NULL)
	{
		r_q->des_access = desired_access;
	}

	r_q->system_name = system_name;
	make_lsa_obj_attr(&(r_q->attr           ), attributes, qos);
}

/*******************************************************************
reads or writes an LSA_Q_OPEN_POL structure.
********************************************************************/
void lsa_io_q_open_pol(char *desc,  LSA_Q_OPEN_POL *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_q_open_pol");
	depth++;

	prs_uint32("ptr       ", ps, depth, &(r_q->ptr       ));
	prs_uint16("system_name", ps, depth, &(r_q->system_name ));
	prs_align ( ps );

	lsa_io_obj_attr("", &(r_q->attr           ), ps, depth);

	if (r_q->attr.ptr_sec_qos == 0)
	{
		prs_uint32("des_access", ps, depth, &(r_q->des_access));
	}
}

/*******************************************************************
reads or writes an LSA_R_OPEN_POL structure.
********************************************************************/
void lsa_io_r_open_pol(char *desc,  LSA_R_OPEN_POL *r_p, prs_struct *ps, int depth)
{
	if (r_p == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_r_open_pol");
	depth++;

	smb_io_pol_hnd("", &(r_p->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_p->status));
}

/*******************************************************************
makes an LSA_Q_OPEN_POL2 structure.
********************************************************************/
void make_q_open_pol2(LSA_Q_OPEN_POL2 *r_q, char *server_name,
			uint32 attributes,
			uint32 desired_access,
			LSA_SEC_QOS *qos)
{
	if (r_q == NULL) return;

	DEBUG(5,("make_open_pol2: attr:%d da:%d\n", attributes, desired_access));

	r_q->ptr = 1; /* undocumented pointer */

	if (qos == NULL)
	{
		r_q->des_access = desired_access;
	}

	make_unistr2     (&(r_q->uni_server_name), server_name, strlen(server_name));
	make_lsa_obj_attr(&(r_q->attr           ), attributes, qos);
}

/*******************************************************************
reads or writes an LSA_Q_OPEN_POL2 structure.
********************************************************************/
void lsa_io_q_open_pol2(char *desc,  LSA_Q_OPEN_POL2 *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_q_open_pol2");
	depth++;

	prs_uint32("ptr       ", ps, depth, &(r_q->ptr       ));

	smb_io_unistr2 ("", &(r_q->uni_server_name), r_q->ptr, ps, depth);
	lsa_io_obj_attr("", &(r_q->attr           ), ps, depth);

	if (r_q->attr.ptr_sec_qos == 0)
	{
		prs_uint32("des_access", ps, depth, &(r_q->des_access));
	}
}

/*******************************************************************
reads or writes an LSA_R_OPEN_POL2 structure.
********************************************************************/
void lsa_io_r_open_pol2(char *desc,  LSA_R_OPEN_POL2 *r_p, prs_struct *ps, int depth)
{
	if (r_p == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_r_open_pol2");
	depth++;

	smb_io_pol_hnd("", &(r_p->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_p->status));
}

/*******************************************************************
makes an LSA_Q_QUERY_INFO structure.
********************************************************************/
void make_q_query(LSA_Q_QUERY_INFO *q_q, POLICY_HND *hnd, uint16 info_class)
{
	if (q_q == NULL || hnd == NULL) return;

	DEBUG(5,("make_q_query\n"));

	memcpy(&(q_q->pol), hnd, sizeof(q_q->pol));

	q_q->info_class = info_class;
}

/*******************************************************************
reads or writes an LSA_Q_QUERY_INFO structure.
********************************************************************/
void lsa_io_q_query(char *desc,  LSA_Q_QUERY_INFO *q_q, prs_struct *ps, int depth)
{
	if (q_q == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_q_query");
	depth++;

	smb_io_pol_hnd("", &(q_q->pol), ps, depth);

	prs_uint16("info_class", ps, depth, &(q_q->info_class));
}

/*******************************************************************
reads or writes an LSA_Q_ENUM_TRUST_DOM structure.
********************************************************************/
void lsa_io_q_enum_trust_dom(char *desc,  LSA_Q_ENUM_TRUST_DOM *q_e, prs_struct *ps, int depth)
{
	if (q_e == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_q_enum_trust_dom");
	depth++;


	smb_io_pol_hnd("", &(q_e->pol), ps, depth);

	prs_uint32("enum_context ", ps, depth, &(q_e->enum_context ));
	prs_uint32("preferred_len", ps, depth, &(q_e->preferred_len));
}

/*******************************************************************
makes an LSA_R_ENUM_TRUST_DOM structure.
********************************************************************/
void make_r_enum_trust_dom(LSA_R_ENUM_TRUST_DOM *r_e,
                           uint32 enum_context, char *domain_name, DOM_SID *domain_sid,
                           uint32 status)
{
	if (r_e == NULL) return;

	DEBUG(5,("make_r_enum_trust_dom\n"));

	r_e->enum_context = enum_context;

	if (status == 0)
	{
		int len_domain_name = strlen(domain_name);

		r_e->num_domains  = 1;
		r_e->ptr_enum_domains = 1;
		r_e->num_domains2 = 1;

		make_uni_hdr2(&(r_e->hdr_domain_name ), len_domain_name, len_domain_name, 4);
		make_unistr2 (&(r_e->uni_domain_name ), domain_name, len_domain_name);
		make_dom_sid2(&(r_e->other_domain_sid), domain_sid);
	}
	else
	{
		r_e->num_domains = 0;
		r_e->ptr_enum_domains = 0;
	}

	r_e->status = status;
}

/*******************************************************************
reads or writes an LSA_R_ENUM_TRUST_DOM structure.
********************************************************************/
void lsa_io_r_enum_trust_dom(char *desc,  LSA_R_ENUM_TRUST_DOM *r_e, prs_struct *ps, int depth)
{
	if (r_e == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_r_enum_trust_dom");
	depth++;

	prs_uint32("enum_context    ", ps, depth, &(r_e->enum_context    ));
	prs_uint32("num_domains     ", ps, depth, &(r_e->num_domains     ));
	prs_uint32("ptr_enum_domains", ps, depth, &(r_e->ptr_enum_domains));

	if (r_e->ptr_enum_domains != 0)
	{
		prs_uint32("num_domains2", ps, depth, &(r_e->num_domains2));
		smb_io_unihdr2 ("", &(r_e->hdr_domain_name ), ps, depth);
		smb_io_unistr2 ("", &(r_e->uni_domain_name ), r_e->hdr_domain_name.buffer, ps, depth);
		smb_io_dom_sid2("", &(r_e->other_domain_sid), ps, depth);
	}

	prs_uint32("status", ps, depth, &(r_e->status));
}

/*******************************************************************
reads or writes an LSA_Q_QUERY_INFO structure.
********************************************************************/
void lsa_io_r_query(char *desc,  LSA_R_QUERY_INFO *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_r_query");
	depth++;

	prs_uint32("undoc_buffer", ps, depth, &(r_q->undoc_buffer));

	if (r_q->undoc_buffer != 0)
	{
		prs_uint16("info_class", ps, depth, &(r_q->info_class));

		switch (r_q->info_class)
		{
			case 3:
			{
				smb_io_dom_query_3("", &(r_q->dom.id3), ps, depth);
				break;
			}
			case 5:
			{
				smb_io_dom_query_5("", &(r_q->dom.id3), ps, depth);
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
}

/*******************************************************************
makes an LSA_Q_CLOSE structure.
********************************************************************/
void make_lsa_q_close(LSA_Q_CLOSE *q_c, POLICY_HND *hnd)
{
	if (q_c == NULL || hnd == NULL) return;

	DEBUG(5,("make_lsa_q_close\n"));

	memcpy(&(q_c->pol), hnd, sizeof(q_c->pol));
}

/*******************************************************************
reads or writes an LSA_Q_CLOSE structure.
********************************************************************/
void lsa_io_q_close(char *desc,  LSA_Q_CLOSE *q_c, prs_struct *ps, int depth)
{
	if (q_c == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_q_close");
	depth++;

	smb_io_pol_hnd("", &(q_c->pol), ps, depth);
}

/*******************************************************************
reads or writes an LSA_R_CLOSE structure.
********************************************************************/
void lsa_io_r_close(char *desc,  LSA_R_CLOSE *r_c, prs_struct *ps, int depth)
{
	if (r_c == NULL) return;

	prs_debug(ps, depth, desc, "lsa_io_r_close");
	depth++;

	smb_io_pol_hnd("", &(r_c->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_c->status));
}

