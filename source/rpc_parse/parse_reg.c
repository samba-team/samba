/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Marc Jacobsen                     1999.
 *  Copyright (C) Simo Sorce                        2000.
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

/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_q_open_hkcr(REG_Q_OPEN_HKCR *q_o,
				uint16 unknown_0, uint32 level)
{
	q_o->ptr = 1;
	q_o->unknown_0 = unknown_0;
	q_o->unknown_1 = 0x0; /* random - changes */
	q_o->level = level;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_open_hkcr(const char *desc,  REG_Q_OPEN_HKCR *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_open_hkcr");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr      ", ps, depth, &r_q->ptr))
		return False;

	if (r_q->ptr != 0) {
		if(!prs_uint16("unknown_0", ps, depth, &r_q->unknown_0))
			return False;
		if(!prs_uint16("unknown_1", ps, depth, &r_q->unknown_1))
			return False;
		if(!prs_uint32("level    ", ps, depth, &r_q->level))
			return False;
	}

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_open_hkcr(const char *desc,  REG_R_OPEN_HKCR *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_open_hkcr");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_r->pol, ps, depth))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

	return True;
}

/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_q_open_hklm(REG_Q_OPEN_HKLM * q_o,
			  uint16 unknown_0, uint32 access_mask)
{
	q_o->ptr = 1;
	q_o->unknown_0 = unknown_0;
	q_o->unknown_1 = 0x0;	/* random - changes */
	q_o->access_mask = access_mask;

}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL reg_io_q_open_hklm(const char *desc, REG_Q_OPEN_HKLM * r_q, prs_struct *ps,
			int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_open_hklm");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("ptr      ", ps, depth, &(r_q->ptr)))
		return False;
	if (r_q->ptr != 0)
	{
		if (!prs_uint16("unknown_0", ps, depth, &(r_q->unknown_0)))
		return False;
		if (!prs_uint16("unknown_1", ps, depth, &(r_q->unknown_1)))
		return False;
		if (!prs_uint32("access_mask", ps, depth, &(r_q->access_mask)))
		return False;
	}

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL reg_io_r_open_hklm(const char *desc, REG_R_OPEN_HKLM * r_r, prs_struct *ps,
			int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_open_hklm");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!smb_io_pol_hnd("", &r_r->pol, ps, depth))
		return False;

	if (!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

	return True;
}


/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_q_flush_key(REG_Q_FLUSH_KEY *q_u, POLICY_HND *pol)
{
	memcpy(&q_u->pol, pol, sizeof(q_u->pol));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_flush_key(const char *desc,  REG_Q_FLUSH_KEY *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_flush_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pol, ps, depth))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_flush_key(const char *desc,  REG_R_FLUSH_KEY *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_flush_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

	return True;
}

/*******************************************************************
reads or writes SEC_DESC_BUF and SEC_DATA structures.
********************************************************************/

static BOOL reg_io_hdrbuf_sec(uint32 ptr, uint32 *ptr3, BUFHDR *hdr_sec, SEC_DESC_BUF *data, prs_struct *ps, int depth)
{
	if (ptr != 0) {
		uint32 hdr_offset;
		uint32 old_offset;
		if(!smb_io_hdrbuf_pre("hdr_sec", hdr_sec, ps, depth, &hdr_offset))
			return False;

		old_offset = prs_offset(ps);

		if (ptr3 != NULL) {
			if(!prs_uint32("ptr3", ps, depth, ptr3))
				return False;
		}

		if (ptr3 == NULL || *ptr3 != 0) {
			if(!sec_io_desc_buf("data   ", &data, ps, depth)) /* JRA - this line is probably wrong... */
				return False;
		}

		if(!smb_io_hdrbuf_post("hdr_sec", hdr_sec, ps, depth, hdr_offset,
		                   data->max_len, data->len))
				return False;
		if(!prs_set_offset(ps, old_offset + data->len + sizeof(uint32) * ((ptr3 != NULL) ? 5 : 3)))
			return False;

		if(!prs_align(ps))
			return False;
	}

	return True;
}

/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_q_create_key(REG_Q_CREATE_KEY *q_c, POLICY_HND *hnd,
				const char *name, const char *class, SEC_ACCESS *sam_access,
				SEC_DESC_BUF *sec_buf)
{
	int len_name  = name  != NULL ? strlen(name ) + 1: 0;
	int len_class = class != NULL ? strlen(class) + 1: 0;

	ZERO_STRUCTP(q_c);

	memcpy(&q_c->pnt_pol, hnd, sizeof(q_c->pnt_pol));

	init_uni_hdr(&q_c->hdr_name, len_name);
	init_unistr2(&q_c->uni_name, name, len_name);

	init_uni_hdr(&q_c->hdr_class, len_class);
	init_unistr2(&q_c->uni_class, class, len_class);

	q_c->reserved = 0x00000000;
	memcpy(&q_c->sam_access, sam_access, sizeof(q_c->sam_access));

	q_c->ptr1 = 1;
	q_c->sec_info = DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;

	q_c->data = sec_buf;
	q_c->ptr2 = 1;
	init_buf_hdr(&q_c->hdr_sec, sec_buf->len, sec_buf->len);
	q_c->ptr3 = 1;
	q_c->unknown_2 = 0x00000000;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_create_key(const char *desc,  REG_Q_CREATE_KEY *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_create_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pnt_pol, ps, depth))
		return False;

	if(!smb_io_unihdr ("", &r_q->hdr_name, ps, depth))
		return False;
	if(!smb_io_unistr2("", &r_q->uni_name, r_q->hdr_name.buffer, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!smb_io_unihdr ("", &r_q->hdr_class, ps, depth))
		return False;
	if(!smb_io_unistr2("", &r_q->uni_class, r_q->hdr_class.buffer, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("reserved", ps, depth, &r_q->reserved))
		return False;
	if(!sec_io_access("sam_access", &r_q->sam_access, ps, depth))
		return False;

	if(!prs_uint32("ptr1", ps, depth, &r_q->ptr1))
		return False;

	if (r_q->ptr1 != 0) {
		if(!prs_uint32("sec_info", ps, depth, &r_q->sec_info))
			return False;
	}

	if(!prs_uint32("ptr2", ps, depth, &r_q->ptr2))
		return False;
	if(!reg_io_hdrbuf_sec(r_q->ptr2, &r_q->ptr3, &r_q->hdr_sec, r_q->data, ps, depth))
		return False;

	if(!prs_uint32("unknown_2", ps, depth, &r_q->unknown_2))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_create_key(const char *desc,  REG_R_CREATE_KEY *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_create_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_r->key_pol, ps, depth))
		return False;
	if(!prs_uint32("unknown", ps, depth, &r_r->unknown))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

	return True;
}


/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_q_delete_val(REG_Q_DELETE_VALUE *q_c, POLICY_HND *hnd,
				const char *name)
{
	int len_name  = name  != NULL ? strlen(name ) + 1: 0;
	ZERO_STRUCTP(q_c);

	memcpy(&q_c->pnt_pol, hnd, sizeof(q_c->pnt_pol));

	init_uni_hdr(&q_c->hdr_name, len_name);
	init_unistr2(&q_c->uni_name, name, len_name);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_delete_val(const char *desc,  REG_Q_DELETE_VALUE *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_delete_val");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pnt_pol, ps, depth))
		return False;

	if(!smb_io_unihdr ("", &r_q->hdr_name, ps, depth))
		return False;
	if(!smb_io_unistr2("", &r_q->uni_name, r_q->hdr_name.buffer, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_delete_val(const char *desc,  REG_R_DELETE_VALUE *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_delete_val");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

	return True;
}

/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_q_delete_key(REG_Q_DELETE_KEY *q_c, POLICY_HND *hnd,
				const char *name)
{
	int len_name  = name  != NULL ? strlen(name ) + 1: 0;
	ZERO_STRUCTP(q_c);

	memcpy(&q_c->pnt_pol, hnd, sizeof(q_c->pnt_pol));

	init_uni_hdr(&q_c->hdr_name, len_name);
	init_unistr2(&q_c->uni_name, name, len_name);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_delete_key(const char *desc,  REG_Q_DELETE_KEY *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_delete_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pnt_pol, ps, depth))
		return False;

	if(!smb_io_unihdr ("", &r_q->hdr_name, ps, depth))
		return False;
	if(!smb_io_unistr2("", &r_q->uni_name, r_q->hdr_name.buffer, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_delete_key(const char *desc,  REG_R_DELETE_KEY *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_delete_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

	return True;
}

/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_q_query_key(REG_Q_QUERY_KEY *q_o, POLICY_HND *hnd,
				uint32 max_class_len)
{
	ZERO_STRUCTP(q_o);

	memcpy(&q_o->pol, hnd, sizeof(q_o->pol));
	init_uni_hdr(&q_o->hdr_class, max_class_len);
	q_o->uni_class.uni_max_len = max_class_len;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_query_key(const char *desc,  REG_Q_QUERY_KEY *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_query_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pol, ps, depth))
		return False;
	if(!smb_io_unihdr ("", &r_q->hdr_class, ps, depth))
		return False;
	if(!smb_io_unistr2("", &r_q->uni_class, r_q->hdr_class.buffer, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	return True;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_query_key(const char *desc,  REG_R_QUERY_KEY *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_query_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_unihdr ("", &r_r->hdr_class, ps, depth))
		return False;
	if(!smb_io_unistr2("", &r_r->uni_class, r_r->hdr_class.buffer, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("num_subkeys   ", ps, depth, &r_r->num_subkeys))
		return False;
	if(!prs_uint32("max_subkeylen ", ps, depth, &r_r->max_subkeylen))
		return False;
	if(!prs_uint32("mak_subkeysize", ps, depth, &r_r->max_subkeysize))
		return False;
	if(!prs_uint32("num_values    ", ps, depth, &r_r->num_values))
		return False;
	if(!prs_uint32("max_valnamelen", ps, depth, &r_r->max_valnamelen))
		return False;
	if(!prs_uint32("max_valbufsize", ps, depth, &r_r->max_valbufsize))
		return False;
	if(!prs_uint32("sec_desc      ", ps, depth, &r_r->sec_desc))
		return False;
	if(!smb_io_time("mod_time     ", &r_r->mod_time, ps, depth))
		return False;
	
	if(!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

	return True;
}

/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_q_unk_1a(REG_Q_UNK_1A *q_o, POLICY_HND *hnd)
{
	memcpy(&q_o->pol, hnd, sizeof(q_o->pol));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_unk_1a(const char *desc,  REG_Q_UNK_1A *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_unk_1a");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pol, ps, depth))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_unk_1a(const char *desc,  REG_R_UNK_1A *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_unk_1a");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("unknown", ps, depth, &r_r->unknown))
		return False;
	if(!prs_ntstatus("status" , ps, depth, &r_r->status))
		return False;

	return True;
}

/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_q_open_hku(REG_Q_OPEN_HKU *q_o,
				uint16 unknown_0, uint32 level)
{
	q_o->ptr = 1;
	q_o->unknown_0 = unknown_0;
	q_o->unknown_1 = 0x0; /* random - changes */
	q_o->level = level;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_open_hku(const char *desc,  REG_Q_OPEN_HKU *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_open_hku");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr      ", ps, depth, &r_q->ptr))
		return False;
	if (r_q->ptr != 0) {
		if(!prs_uint16("unknown_0", ps, depth, &r_q->unknown_0))
			return False;
		if(!prs_uint16("unknown_1", ps, depth, &r_q->unknown_1))
			return False;
		if(!prs_uint32("level    ", ps, depth, &r_q->level))
			return False;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_open_hku(const char *desc,  REG_R_OPEN_HKU *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_open_hku");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_r->pol, ps, depth))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

	return True;
}

/*******************************************************************
 Inits an REG_Q_CLOSE structure.
********************************************************************/

void init_reg_q_close(REG_Q_CLOSE *q_c, POLICY_HND *hnd)
{
	DEBUG(5,("init_reg_q_close\n"));

	memcpy(&q_c->pol, hnd, sizeof(q_c->pol));
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_close(const char *desc,  REG_Q_CLOSE *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_unknown_1");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("", &q_u->pol, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_close(const char *desc,  REG_R_CLOSE *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_unknown_1");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_pol_hnd("", &r_u->pol, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_u->status))
		return False;

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/

void init_reg_q_set_key_sec(REG_Q_SET_KEY_SEC *q_i, POLICY_HND *pol, SEC_DESC_BUF *sec_desc_buf)
{
	memcpy(&q_i->pol, pol, sizeof(q_i->pol));

	q_i->sec_info = DACL_SECURITY_INFORMATION;

	q_i->ptr = 1;
	init_buf_hdr(&q_i->hdr_sec, sec_desc_buf->len, sec_desc_buf->len);
	q_i->data = sec_desc_buf;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_set_key_sec(const char *desc,  REG_Q_SET_KEY_SEC *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_set_key_sec");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pol, ps, depth))
		return False;

	if(!prs_uint32("sec_info", ps, depth, &r_q->sec_info))
		return False;
	if(!prs_uint32("ptr    ", ps, depth, &r_q->ptr))
		return False;

	if(!reg_io_hdrbuf_sec(r_q->ptr, NULL, &r_q->hdr_sec, r_q->data, ps, depth))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_set_key_sec(const char *desc, REG_R_SET_KEY_SEC *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_set_key_sec");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_ntstatus("status", ps, depth, &r_q->status))
		return False;

	return True;
}


/*******************************************************************
makes a structure.
********************************************************************/

void init_reg_q_get_key_sec(REG_Q_GET_KEY_SEC *q_i, POLICY_HND *pol, 
				uint32 sec_buf_size, SEC_DESC_BUF *psdb)
{
	memcpy(&q_i->pol, pol, sizeof(q_i->pol));

	q_i->sec_info = OWNER_SECURITY_INFORMATION |
	                GROUP_SECURITY_INFORMATION |
	                DACL_SECURITY_INFORMATION;

	q_i->ptr = psdb != NULL ? 1 : 0;
	q_i->data = psdb;

	init_buf_hdr(&q_i->hdr_sec, sec_buf_size, 0);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_get_key_sec(const char *desc,  REG_Q_GET_KEY_SEC *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_get_key_sec");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pol, ps, depth))
		return False;

	if(!prs_uint32("sec_info", ps, depth, &r_q->sec_info))
		return False;
	if(!prs_uint32("ptr     ", ps, depth, &r_q->ptr))
		return False;

	if(!reg_io_hdrbuf_sec(r_q->ptr, NULL, &r_q->hdr_sec, r_q->data, ps, depth))
		return False;

	return True;
}

#if 0
/*******************************************************************
makes a structure.
********************************************************************/
 void init_reg_r_get_key_sec(REG_R_GET_KEY_SEC *r_i, POLICY_HND *pol, 
				uint32 buf_len, uint8 *buf,
				NTSTATUS status)
{
	r_i->ptr = 1;
	init_buf_hdr(&r_i->hdr_sec, buf_len, buf_len);
	init_sec_desc_buf(r_i->data, buf_len, 1);

	r_i->status = status; /* 0x0000 0000 or 0x0000 007a */
}
#endif 

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_get_key_sec(const char *desc,  REG_R_GET_KEY_SEC *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_get_key_sec");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr      ", ps, depth, &r_q->ptr))
		return False;

	if (r_q->ptr != 0) {
		if(!smb_io_hdrbuf("", &r_q->hdr_sec, ps, depth))
			return False;
		if(!sec_io_desc_buf("", &r_q->data, ps, depth))
			return False;
		if(!prs_align(ps))
			return False;
	}

	if(!prs_ntstatus("status", ps, depth, &r_q->status))
		return False;

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/

BOOL init_reg_q_info(REG_Q_INFO *q_i, POLICY_HND *pol, char* val_name)
{
        int len_type = val_name != NULL ? strlen(val_name) + 1 : 0;

        if (q_i == NULL)
                return False;

        q_i->pol = *pol;

        init_uni_hdr(&(q_i->hdr_type), len_type);
        init_unistr2(&(q_i->uni_type), val_name, len_type);

        q_i->ptr_reserved = 1;
        q_i->ptr_buf = 1;

        q_i->ptr_bufsize = 1;
        q_i->bufsize = 0;
        q_i->buf_unk = 0;

        q_i->unk1 = 0;
        q_i->ptr_buflen = 1;
        q_i->buflen = 0;

        q_i->ptr_buflen2 = 1;
        q_i->buflen2 = 0;

        return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_info(const char *desc,  REG_Q_INFO *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_info");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pol, ps, depth))
		return False;
	if(!smb_io_unihdr ("", &r_q->hdr_type, ps, depth))
		return False;
	if(!smb_io_unistr2("", &r_q->uni_type, r_q->hdr_type.buffer, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_reserved", ps, depth, &(r_q->ptr_reserved)))
		return False;

	if(!prs_uint32("ptr_buf", ps, depth, &(r_q->ptr_buf)))
		return False;

	if(r_q->ptr_buf) {
		if(!prs_uint32("ptr_bufsize", ps, depth, &(r_q->ptr_bufsize)))
			return False;
		if(!prs_uint32("bufsize", ps, depth, &(r_q->bufsize)))
			return False;
		if(!prs_uint32("buf_unk", ps, depth, &(r_q->buf_unk)))
			return False;
	}

	if(!prs_uint32("unk1", ps, depth, &(r_q->unk1)))
		return False;

	if(!prs_uint32("ptr_buflen", ps, depth, &(r_q->ptr_buflen)))
		return False;

	if (r_q->ptr_buflen) {
		if(!prs_uint32("buflen", ps, depth, &(r_q->buflen)))
			return False;
		if(!prs_uint32("ptr_buflen2", ps, depth, &(r_q->ptr_buflen2)))
			return False;
		if(!prs_uint32("buflen2", ps, depth, &(r_q->buflen2)))
			return False;
	}

 	return True;
}

/*******************************************************************
 Inits a structure.
********************************************************************/

BOOL init_reg_r_info(uint32 include_keyval, REG_R_INFO *r_r,
		     BUFFER2* buf, uint32 type, NTSTATUS status)
{
  if(r_r == NULL)
    return False;

  
  r_r->ptr_type = 1;
  r_r->type = type;

  /* if include_keyval is not set, don't send the key value, just
     the buflen data. probably used by NT5 to allocate buffer space - SK */
  r_r->ptr_uni_val = include_keyval ? 1:0;
  r_r->uni_val = buf;

  r_r->ptr_max_len = 1;
  r_r->buf_max_len = r_r->uni_val->buf_max_len;

  r_r->ptr_len = 1;
  r_r->buf_len = r_r->uni_val->buf_len;

  r_r->status = status;

  return True;
  
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_info(const char *desc, REG_R_INFO *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_info");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("ptr_type", ps, depth, &(r_r->ptr_type)))
		return False;

	if (r_r->ptr_type != 0) {
		if(!prs_uint32("type", ps, depth, &r_r->type))
			return False;
	}

	if(!prs_uint32("ptr_uni_val", ps, depth, &(r_r->ptr_uni_val)))
		return False;

	if(r_r->ptr_uni_val != 0) {
		if(!smb_io_buffer2("uni_val", r_r->uni_val, r_r->ptr_uni_val, ps, depth))
			return False;
	}

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_max_len", ps, depth, &(r_r->ptr_max_len)))
		return False;

	if (r_r->ptr_max_len != 0) {
		if(!prs_uint32("buf_max_len", ps, depth, &(r_r->buf_max_len)))
		return False;
	}

	if(!prs_uint32("ptr_len", ps, depth, &(r_r->ptr_len)))
		return False;
	if (r_r->ptr_len != 0) {
		if(!prs_uint32("buf_len", ps, depth, &(r_r->buf_len)))
			return False;
	}

	if(!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

 	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/

void init_reg_q_enum_val(REG_Q_ENUM_VALUE *q_i, POLICY_HND *pol,
				uint32 val_idx, uint32 max_val_len,
				uint32 max_buf_len)
{
	ZERO_STRUCTP(q_i);

	memcpy(&q_i->pol, pol, sizeof(q_i->pol));

	q_i->val_index = val_idx;
	init_uni_hdr(&q_i->hdr_name, max_val_len);
	q_i->uni_name.uni_max_len = max_val_len;
	
	q_i->ptr_type = 1;
	q_i->type = 0x0;

	q_i->ptr_value = 1;
	q_i->buf_value.buf_max_len = max_buf_len;

	q_i->ptr1 = 1;
	q_i->len_value1 = max_buf_len;

	q_i->ptr2 = 1;
	q_i->len_value2 = 0;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_enum_val(const char *desc,  REG_Q_ENUM_VALUE *q_q, prs_struct *ps, int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_enum_val");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &q_q->pol, ps, depth))
		return False;
	
	if(!prs_uint32("val_index", ps, depth, &q_q->val_index))
		return False;
	if(!smb_io_unihdr ("hdr_name", &q_q->hdr_name, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_name", &q_q->uni_name, q_q->hdr_name.buffer, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_type", ps, depth, &q_q->ptr_type))
		return False;

	if (q_q->ptr_type != 0) {
		if(!prs_uint32("type", ps, depth, &q_q->type))
			return False;
	}

	if(!prs_uint32("ptr_value", ps, depth, &q_q->ptr_value))
		return False;
	if(!smb_io_buffer2("buf_value", &q_q->buf_value, q_q->ptr_value, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr1", ps, depth, &q_q->ptr1))
		return False;
	if (q_q->ptr1 != 0) {
		if(!prs_uint32("len_value1", ps, depth, &q_q->len_value1))
			return False;
	}
	if(!prs_uint32("ptr2", ps, depth, &q_q->ptr2))
		return False;
	if (q_q->ptr2 != 0) {
		if(!prs_uint32("len_value2", ps, depth, &q_q->len_value2))
			return False;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_enum_val(const char *desc,  REG_R_ENUM_VALUE *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_enum_val");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_unihdr ("hdr_name", &r_q->hdr_name, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_name", &r_q->uni_name, r_q->hdr_name.buffer, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_type", ps, depth, &r_q->ptr_type))
		return False;

	if (r_q->ptr_type != 0) {
		if(!prs_uint32("type", ps, depth, &r_q->type))
			return False;
	}

	if(!prs_uint32("ptr_value", ps, depth, &r_q->ptr_value))
		return False;
	if(!smb_io_buffer2("buf_value", r_q->buf_value, r_q->ptr_value, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr1", ps, depth, &r_q->ptr1))
		return False;
	if (r_q->ptr1 != 0) {
		if(!prs_uint32("len_value1", ps, depth, &r_q->len_value1))
			return False;
	}

	if(!prs_uint32("ptr2", ps, depth, &r_q->ptr2))
		return False;
	if (r_q->ptr2 != 0) {
		if(!prs_uint32("len_value2", ps, depth, &r_q->len_value2))
			return False;
	}

	if(!prs_ntstatus("status", ps, depth, &r_q->status))
		return False;

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/

void init_reg_q_create_val(REG_Q_CREATE_VALUE *q_i, POLICY_HND *pol,
				const char *val_name, uint32 type,
				BUFFER3 *val)
{
	int val_len = strlen(val_name) + 1;

	ZERO_STRUCTP(q_i);

	memcpy(&q_i->pol, pol, sizeof(q_i->pol));

	init_uni_hdr(&q_i->hdr_name, val_len);
	init_unistr2(&q_i->uni_name, val_name, val_len);
	
	q_i->type      = type;
	q_i->buf_value = val;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_create_val(const char *desc,  REG_Q_CREATE_VALUE *q_q, prs_struct *ps, int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_create_val");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &q_q->pol, ps, depth))
		return False;
	
	if(!smb_io_unihdr ("hdr_name", &q_q->hdr_name, ps, depth))
		return False;
	if(!smb_io_unistr2("uni_name", &q_q->uni_name, q_q->hdr_name.buffer, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("type", ps, depth, &q_q->type))
		return False;
	if(!smb_io_buffer3("buf_value", q_q->buf_value, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_create_val(const char *desc,  REG_R_CREATE_VALUE *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_create_val");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_ntstatus("status", ps, depth, &r_q->status))
		return False;

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/

void init_reg_q_enum_key(REG_Q_ENUM_KEY *q_i, POLICY_HND *pol, uint32 key_idx)
{
	memcpy(&q_i->pol, pol, sizeof(q_i->pol));

	q_i->key_index = key_idx;
	q_i->key_name_len = 0;
	q_i->unknown_1 = 0x0414;

	q_i->ptr1 = 1;
	q_i->unknown_2 = 0x0000020A;
	memset(q_i->pad1, 0, sizeof(q_i->pad1));

	q_i->ptr2 = 1;
	memset(q_i->pad2, 0, sizeof(q_i->pad2));

	q_i->ptr3 = 1;
	unix_to_nt_time(&q_i->time, 0);            /* current time? */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_enum_key(const char *desc,  REG_Q_ENUM_KEY *q_q, prs_struct *ps, int depth)
{
	if (q_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_enum_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &q_q->pol, ps, depth))
		return False;
	
	if(!prs_uint32("key_index", ps, depth, &q_q->key_index))
		return False;
	if(!prs_uint16("key_name_len", ps, depth, &q_q->key_name_len))
		return False;
	if(!prs_uint16("unknown_1", ps, depth, &q_q->unknown_1))
		return False;

	if(!prs_uint32("ptr1", ps, depth, &q_q->ptr1))
		return False;

	if (q_q->ptr1 != 0) {
		if(!prs_uint32("unknown_2", ps, depth, &q_q->unknown_2))
			return False;
		if(!prs_uint8s(False, "pad1", ps, depth, q_q->pad1, sizeof(q_q->pad1)))
			return False;
	}

	if(!prs_uint32("ptr2", ps, depth, &q_q->ptr2))
		return False;

	if (q_q->ptr2 != 0) {
		if(!prs_uint8s(False, "pad2", ps, depth, q_q->pad2, sizeof(q_q->pad2)))
			return False;
	}

	if(!prs_uint32("ptr3", ps, depth, &q_q->ptr3))
		return False;

	if (q_q->ptr3 != 0) {
		if(!smb_io_time("", &q_q->time, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_enum_key(const char *desc,  REG_R_ENUM_KEY *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_enum_key");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint16("key_name_len", ps, depth, &r_q->key_name_len))
		return False;
	if(!prs_uint16("unknown_1", ps, depth, &r_q->unknown_1))
		return False;

	if(!prs_uint32("ptr1", ps, depth, &r_q->ptr1))
		return False;

	if (r_q->ptr1 != 0) {
		if(!prs_uint32("unknown_2", ps, depth, &r_q->unknown_2))
			return False;
		if(!prs_uint32("unknown_3", ps, depth, &r_q->unknown_3))
			return False;
		if(!smb_io_unistr3("key_name", &r_q->key_name, ps, depth))
			return False;
		if(!prs_align(ps))
			return False;
	}

	if(!prs_uint32("ptr2", ps, depth, &r_q->ptr2))
		return False;

	if (r_q->ptr2 != 0) {
		if(!prs_uint8s(False, "pad2", ps, depth, r_q->pad2, sizeof(r_q->pad2)))
			return False;
	}

	if(!prs_uint32("ptr3", ps, depth, &r_q->ptr3))
		return False;

	if (r_q->ptr3 != 0) {
		if(!smb_io_time("", &r_q->time, ps, depth))
			return False;
	}

	if(!prs_ntstatus("status", ps, depth, &r_q->status))
		return False;

	return True;
}

/*******************************************************************
makes a structure.
********************************************************************/

void init_reg_q_open_entry(REG_Q_OPEN_ENTRY *r_q, POLICY_HND *pol,
				const char *key_name, uint32 unk)
{
	int len_name = strlen(key_name)+1;

	memcpy(&r_q->pol, pol, sizeof(r_q->pol));

	init_uni_hdr(&r_q->hdr_name, len_name);
	init_unistr2(&r_q->uni_name, key_name, len_name);

	r_q->unknown_0 = 0x00000000;
	r_q->unknown_1 = unk;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_q_open_entry(const char *desc,  REG_Q_OPEN_ENTRY *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_entry");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_q->pol, ps, depth))
		return False;
	if(!smb_io_unihdr ("", &r_q->hdr_name, ps, depth))
		return False;
	if(!smb_io_unistr2("", &r_q->uni_name, r_q->hdr_name.buffer, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("unknown_0", ps, depth, &r_q->unknown_0))
		return False;
	if(!prs_uint32("unknown_1", ps, depth, &r_q->unknown_1))
		return False;

	return True;
}

/*******************************************************************
 Inits a structure.
********************************************************************/

void init_reg_r_open_entry(REG_R_OPEN_ENTRY *r_r,
			   POLICY_HND *pol, NTSTATUS status)
{
	memcpy(&r_r->pol, pol, sizeof(r_r->pol));
	r_r->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/

BOOL reg_io_r_open_entry(const char *desc,  REG_R_OPEN_ENTRY *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_open_entry");
	depth++;

	if(!prs_align(ps))
		return False;
	
	if(!smb_io_pol_hnd("", &r_r->pol, ps, depth))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_r->status))
		return False;

	return True;
}

/*******************************************************************
Inits a structure.
********************************************************************/
void init_reg_q_shutdown(REG_Q_SHUTDOWN * q_s,
			 const char *msg, uint32 timeout, uint16 flags)
{
	int msg_len;
	msg_len = strlen(msg);

	q_s->ptr_0 = 1;
	q_s->ptr_1 = 1;
	q_s->ptr_2 = 1;

	init_uni_hdr(&(q_s->hdr_msg), msg_len);
	init_unistr2(&(q_s->uni_msg), msg, msg_len);

	q_s->timeout = timeout;
	q_s->flags = flags;

}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL reg_io_q_shutdown(const char *desc, REG_Q_SHUTDOWN * q_s, prs_struct *ps,
		       int depth)
{
	if (q_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_shutdown");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("ptr_0", ps, depth, &(q_s->ptr_0)))
		return False;
	if (!prs_uint32("ptr_1", ps, depth, &(q_s->ptr_1)))
		return False;
	if (!prs_uint32("ptr_2", ps, depth, &(q_s->ptr_2)))
		return False;

	if (!smb_io_unihdr("hdr_msg", &(q_s->hdr_msg), ps, depth))
		return False;
	if (!smb_io_unistr2("uni_msg", &(q_s->uni_msg), q_s->hdr_msg.buffer, ps, depth))
		return False;
	if (!prs_align(ps))
		return False;

	if (!prs_uint32("timeout", ps, depth, &(q_s->timeout)))
		return False;
	if (!prs_uint16("flags  ", ps, depth, &(q_s->flags)))
		return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL reg_io_r_shutdown(const char *desc, REG_R_SHUTDOWN * r_s, prs_struct *ps,
		       int depth)
{
	if (r_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_shutdown");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_ntstatus("status", ps, depth, &r_s->status))
		return False;

	return True;
}

/*******************************************************************
Inits a structure.
********************************************************************/
void init_reg_q_abort_shutdown(REG_Q_ABORT_SHUTDOWN * q_s)
{

	q_s->ptr_server = 0;

}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL reg_io_q_abort_shutdown(const char *desc, REG_Q_ABORT_SHUTDOWN * q_s,
			     prs_struct *ps, int depth)
{
	if (q_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_q_abort_shutdown");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_uint32("ptr_server", ps, depth, &(q_s->ptr_server)))
		return False;
	if (q_s->ptr_server != 0)
		if (!prs_uint16("server", ps, depth, &(q_s->server)))
			return False;

	return True;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
BOOL reg_io_r_abort_shutdown(const char *desc, REG_R_ABORT_SHUTDOWN * r_s,
			     prs_struct *ps, int depth)
{
	if (r_s == NULL)
		return False;

	prs_debug(ps, depth, desc, "reg_io_r_abort_shutdown");
	depth++;

	if (!prs_align(ps))
		return False;

	if (!prs_ntstatus("status", ps, depth, &r_s->status))
		return False;

	return True;
}
