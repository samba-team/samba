/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Luke Leighton 1996 - 1997
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

extern int DEBUGLEVEL;


/*******************************************************************
reads or writes an LSA_Q_QUERY_INFO structure.
********************************************************************/
char* lsa_io_q_query(BOOL io, LSA_Q_QUERY_INFO *q_q, char *q, char *base, int align)
{
	if (q_q == NULL) return NULL;

	RW_SVAL(io, q, q_q->info_class, 0); q += 2;

	return q;
}

/*******************************************************************
reads or writes an LSA_Q_QUERY_INFO structure.
********************************************************************/
char* lsa_io_r_query(BOOL io, LSA_R_QUERY_INFO *r_q, char *q, char *base, int align)
{
	if (r_q == NULL) return NULL;

	RW_IVAL(io, q, r_q->undoc_buffer, 0); q += 4;

	if (r_q->undoc_buffer != 0)
	{
		RW_SVAL(io, q, r_q->info_class, 0); q += 2;

		switch (r_q->info_class)
		{
			case 3:
			{
				q = smb_io_dom_query_3(io, &(r_q->dom.id3), q, base, align);
				break;
			}
			case 5:
			{
				q = smb_io_dom_query_5(io, &(r_q->dom.id3), q, base, align);
				break;
			}
			default:
			{
				/* PANIC! */
				break;
			}
		}
	}
	return q;
}

#if 0
/*******************************************************************
reads or writes a structure.
********************************************************************/
 char* smb_io_(BOOL io, *, char *q, char *base, int align)
{
	if (== NULL) return NULL;

	q = align_offset(q, base, align);
	
	RW_IVAL(io, q, , 0); q += 4;

	return q;
}
#endif
