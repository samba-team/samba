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

extern int DEBUGLEVEL;


/*******************************************************************
creates a structure.
********************************************************************/
void make_reg_q_open_policy(REG_Q_OPEN_POLICY *r_q,
				uint16 unknown_0, uint32 level, uint16 unknown_1)
{
	r_q->ptr = 1;
	r_q->unknown_0 = unknown_0;
	r_q->level = level;
	r_q->unknown_1 = unknown_1;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void reg_io_q_open_policy(char *desc,  REG_Q_OPEN_POLICY *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL) return;

	prs_debug(ps, depth, desc, "reg_io_q_open_policy");
	depth++;

	prs_align(ps);
	
	prs_uint32("ptr      ", ps, depth, &(r_q->ptr      ));
	if (r_q->ptr != 0)
	{
		prs_uint16("unknown_0", ps, depth, &(r_q->unknown_0));
		prs_uint32("level    ", ps, depth, &(r_q->level    ));
		prs_uint16("unknown_1", ps, depth, &(r_q->unknown_1));
	}
}


/*******************************************************************
creates a structure.
********************************************************************/
void make_reg_r_open_policy(REG_R_OPEN_POLICY *r_r,
				POLICY_HND *pol, uint32 status)
{
	if (r_r == NULL) return;

	memcpy(&(r_r->pol), pol, sizeof(r_r->pol));
	r_r->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void reg_io_r_open_policy(char *desc,  REG_R_OPEN_POLICY *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL) return;

	prs_debug(ps, depth, desc, "reg_io_r_open_policy");
	depth++;

	prs_align(ps);
	
	smb_io_pol_hnd("", &(r_r->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_r->status));
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
void reg_io_q_close(char *desc,  REG_Q_CLOSE *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL) return;

	prs_debug(ps, depth, desc, "reg_io_q_unknown_1");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(q_u->pol), ps, depth); 
	prs_align(ps);
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void reg_io_r_close(char *desc,  REG_R_CLOSE *r_u, prs_struct *ps, int depth)
{
	if (r_u == NULL) return;

	prs_debug(ps, depth, desc, "reg_io_r_unknown_1");
	depth++;

	prs_align(ps);

	smb_io_pol_hnd("", &(r_u->pol), ps, depth); 
	prs_align(ps);

	prs_uint32("status", ps, depth, &(r_u->status));
}
/*******************************************************************
creates a structure.
********************************************************************/
void make_reg_q_info(REG_Q_INFO *r_q,
				POLICY_HND *pol, char *product_type,
				NTTIME *prod_time, uint8 major_version, uint8 minor_version,
				uint32 unknown)
{
	int type_len = strlen(product_type);

	memcpy(&(r_q->pol), pol, sizeof(r_q->pol));
	make_uni_hdr(&(r_q->hdr_type), type_len, type_len, 1);
	make_unistr2(&(r_q->uni_type), product_type, type_len);

	r_q->ptr1 = 1;
	memcpy(&(r_q->time), prod_time, sizeof(r_q->time));
	r_q->major_version1 = major_version;
	r_q->minor_version1 = minor_version;
	bzero(&(r_q->pad1), sizeof(r_q->pad1));

	r_q->ptr2 = 1;
	r_q->major_version2 = major_version;
	r_q->minor_version2 = minor_version;
	bzero(&(r_q->pad2), sizeof(r_q->pad2));

	r_q->ptr3 = 1;
	r_q->unknown = unknown;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void reg_io_q_info(char *desc,  REG_Q_INFO *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL) return;

	prs_debug(ps, depth, desc, "reg_io_q_info");
	depth++;

	prs_align(ps);
	
	smb_io_pol_hnd("", &(r_q->pol), ps, depth); 
	smb_io_unihdr ("", &(r_q->hdr_type), ps, depth);
	smb_io_unistr2("", &(r_q->uni_type), r_q->hdr_type.buffer, ps, depth);

	prs_uint32("ptr1", ps, depth, &(r_q->ptr1));

	if (r_q->ptr1 != 0)
	{
		smb_io_time("", &(r_q->time), ps, depth);
		prs_uint8 ("major_version1", ps, depth, &(r_q->major_version1));
		prs_uint8 ("minor_version1", ps, depth, &(r_q->minor_version1));
		prs_uint8s(False, "pad1", ps, depth, r_q->pad1, sizeof(r_q->pad1));
	}

	prs_uint32("ptr2", ps, depth, &(r_q->ptr2));

	if (r_q->ptr2 != 0)
	{
		prs_uint8 ("major_version2", ps, depth, &(r_q->major_version2));
		prs_uint8 ("minor_version2", ps, depth, &(r_q->minor_version2));
		prs_uint8s(False, "pad2", ps, depth, r_q->pad2, sizeof(r_q->pad2));
	}

	prs_uint32("ptr3", ps, depth, &(r_q->ptr3));

	if (r_q->ptr3 != 0)
	{
		prs_uint32("unknown", ps, depth, &(r_q->unknown));
	}
}


/*******************************************************************
creates a structure.
********************************************************************/
void make_reg_r_info(REG_R_INFO *r_r,
				uint32 level, char *os_type,
				uint32 unknown_0, uint32 unknown_1,
				uint32 status)
{
	int type_len = strlen(os_type);

	r_r->ptr1 = 1;
	r_r->level = level;

	r_r->ptr_type = 1;
	make_uninotstr2(&(r_r->uni_type), os_type, type_len);

	r_r->ptr2 = 1;
	r_r->unknown_0 = unknown_0;

	r_r->ptr3 = 1;
	r_r->unknown_1 = unknown_1;

	r_r->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void reg_io_r_info(char *desc,  REG_R_INFO *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL) return;

	prs_debug(ps, depth, desc, "reg_io_r_info");
	depth++;

	prs_align(ps);
	
	prs_uint32("ptr1", ps, depth, &(r_r->ptr1));

	if (r_r->ptr1 != 0)
	{
		prs_uint32("level", ps, depth, &(r_r->level));

		prs_uint32("ptr_type", ps, depth, &(r_r->ptr_type));
		smb_io_uninotstr2("", &(r_r->uni_type), r_r->ptr_type, ps, depth);
		prs_align(ps);

		prs_uint32("ptr2", ps, depth, &(r_r->ptr2));

		if (r_r->ptr2 != 0)
		{
			prs_uint32("unknown_0", ps, depth, &(r_r->unknown_0));
		}

		prs_uint32("ptr3", ps, depth, &(r_r->ptr3));

		if (r_r->ptr3 != 0)
		{
			prs_uint32("unknown_1", ps, depth, &(r_r->unknown_1));
		}
	}

	prs_uint32("status", ps, depth, &(r_r->status));
}


/*******************************************************************
creates a structure.
********************************************************************/
void make_reg_q_open_entry(REG_Q_OPEN_ENTRY *r_q,
				POLICY_HND *pol, char *name,
				uint32 unknown_0, uint32 unknown_1, uint16 unknown_2)
{
	int len_name = strlen(name);

	memcpy(&(r_q->pol), pol, sizeof(r_q->pol));

	make_uni_hdr(&(r_q->hdr_name), len_name, len_name, 1);
	make_unistr2(&(r_q->uni_name), name, len_name);

	r_q->unknown_0 = unknown_0;
	r_q->unknown_1 = unknown_1;
	r_q->unknown_2 = unknown_2;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void reg_io_q_open_entry(char *desc,  REG_Q_OPEN_ENTRY *r_q, prs_struct *ps, int depth)
{
	if (r_q == NULL) return;

	prs_debug(ps, depth, desc, "reg_io_q_entry");
	depth++;

	prs_align(ps);
	
	smb_io_pol_hnd("", &(r_q->pol), ps, depth);
	smb_io_unihdr ("", &(r_q->hdr_name), ps, depth);
	smb_io_unistr2("", &(r_q->uni_name), r_q->hdr_name.buffer, ps, depth);

	prs_uint32("unknown_0", ps, depth, &(r_q->unknown_0));
	prs_uint16("unknown_1", ps, depth, &(r_q->unknown_1));
	prs_uint16("unknown_2", ps, depth, &(r_q->unknown_2));
}


/*******************************************************************
creates a structure.
********************************************************************/
void make_reg_r_open_entry(REG_R_OPEN_ENTRY *r_r,
				POLICY_HND *pol, uint32 status)
{
	if (r_r == NULL) return;

	memcpy(&(r_r->pol), pol, sizeof(r_r->pol));
	r_r->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
void reg_io_r_open_entry(char *desc,  REG_R_OPEN_ENTRY *r_r, prs_struct *ps, int depth)
{
	if (r_r == NULL) return;

	prs_debug(ps, depth, desc, "reg_io_r_open_entry");
	depth++;

	prs_align(ps);
	
	smb_io_pol_hnd("", &(r_r->pol), ps, depth);

	prs_uint32("status", ps, depth, &(r_r->status));
}

