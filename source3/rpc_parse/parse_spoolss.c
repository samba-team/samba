/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Jean François Micouleau      1998-2000,
 *  Copyright (C) Gerald Carter                2000-2002,
 *  Copyright (C) Tim Potter		       2001-2002.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
 * return the length of a uint32 (obvious, but the code is clean)
 ********************************************************************/

static uint32 size_of_uint32(uint32 *value)
{
	return (sizeof(*value));
}

/*******************************************************************
return the size required by a struct in the stream
********************************************************************/  
uint32 spoolss_size_printer_enum_values(PRINTER_ENUM_VALUES *p)
{
	uint32 	size = 0; 
	
	if (!p)
		return 0;
	
	/* uint32(offset) + uint32(length) + length) */
	size += (size_of_uint32(&p->value_len)*2) + p->value_len;
	size += (size_of_uint32(&p->data_len)*2) + p->data_len + (p->data_len%2) ;
	
	size += size_of_uint32(&p->type);
		       
	return size;
}

/*******************************************************************
 make a BUFFER5 struct from a uint16*
 ******************************************************************/

bool make_spoolss_buffer5(TALLOC_CTX *mem_ctx, BUFFER5 *buf5, uint32 len, uint16 *src)
{

	buf5->buf_len = len;
	if (src) {
		if (len) {
			if((buf5->buffer=(uint16*)TALLOC_MEMDUP(mem_ctx, src, sizeof(uint16)*len)) == NULL) {
				DEBUG(0,("make_spoolss_buffer5: Unable to malloc memory for buffer!\n"));
				return False;
			}
		} else {
			buf5->buffer = NULL;
		}
	} else {
		buf5->buffer=NULL;
	}
	
	return True;
}

/*******************************************************************
********************************************************************/  

bool make_spoolss_q_enumprinterdataex(SPOOL_Q_ENUMPRINTERDATAEX *q_u,
				      const POLICY_HND *hnd, const char *key,
				      uint32 size)
{
	memcpy(&q_u->handle, hnd, sizeof(q_u->handle));
	init_unistr2(&q_u->key, key, UNI_STR_TERMINATE);
	q_u->size = size;

	return True;
}

/*******************************************************************
 * read a structure.
 ********************************************************************/  

bool spoolss_io_q_enumprinterdataex(const char *desc, SPOOL_Q_ENUMPRINTERDATAEX *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "spoolss_io_q_enumprinterdataex");
	depth++;

	if(!prs_align(ps))
		return False;
	if(!smb_io_pol_hnd("printer handle", &q_u->handle, ps, depth))
		return False;
		
	if(!smb_io_unistr2("", &q_u->key, True, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;
	
	if(!prs_uint32("size", ps, depth, &q_u->size))
		return False;

	return True;
}

/*******************************************************************
********************************************************************/  

static bool spoolss_io_printer_enum_values_ctr(const char *desc, prs_struct *ps, 
				PRINTER_ENUM_VALUES_CTR *ctr, int depth)
{
	int 	i;
	uint32	valuename_offset,
		data_offset,
		current_offset;
	const uint32 basic_unit = 20; /* size of static portion of enum_values */

	prs_debug(ps, depth, desc, "spoolss_io_printer_enum_values_ctr");
	depth++;	

	/* 
	 * offset data begins at 20 bytes per structure * size_of_array.
	 * Don't forget the uint32 at the beginning 
	 * */
	
	current_offset = basic_unit * ctr->size_of_array;
	
	/* first loop to write basic enum_value information */
	
	if (UNMARSHALLING(ps) && ctr->size_of_array) {
		ctr->values = PRS_ALLOC_MEM(ps, PRINTER_ENUM_VALUES, ctr->size_of_array);
		if (!ctr->values)
			return False;
	}

	for (i=0; i<ctr->size_of_array; i++) {
		uint32 base_offset, return_offset;

		base_offset = prs_offset(ps);

		valuename_offset = current_offset;
		if (!prs_uint32("valuename_offset", ps, depth, &valuename_offset))
			return False;

		/* Read or write the value. */

		return_offset = prs_offset(ps);

		if (!prs_set_offset(ps, base_offset + valuename_offset)) {
			return False;
		}

		if (!prs_unistr("valuename", ps, depth, &ctr->values[i].valuename))
			return False;

		/* And go back. */
		if (!prs_set_offset(ps, return_offset))
			return False;

		if (!prs_uint32("value_len", ps, depth, &ctr->values[i].value_len))
			return False;
	
		if (!prs_uint32("type", ps, depth, &ctr->values[i].type))
			return False;
	
		data_offset = ctr->values[i].value_len + valuename_offset;
		
		if (!prs_uint32("data_offset", ps, depth, &data_offset))
			return False;

		if (!prs_uint32("data_len", ps, depth, &ctr->values[i].data_len))
			return False;
			
		/* Read or write the data. */

		return_offset = prs_offset(ps);

		if (!prs_set_offset(ps, base_offset + data_offset)) {
			return False;
		}

		if ( ctr->values[i].data_len ) {
			if ( UNMARSHALLING(ps) ) {
				ctr->values[i].data = PRS_ALLOC_MEM(ps, uint8, ctr->values[i].data_len);
				if (!ctr->values[i].data)
					return False;
			}
			if (!prs_uint8s(False, "data", ps, depth, ctr->values[i].data, ctr->values[i].data_len))
				return False;
		}

		current_offset  = data_offset + ctr->values[i].data_len - basic_unit;
		/* account for 2 byte alignment */
		current_offset += (current_offset % 2);

		/* Remember how far we got. */
		data_offset = prs_offset(ps);

		/* And go back. */
		if (!prs_set_offset(ps, return_offset))
			return False;

	}

	/* Go to the last data offset we got to. */

	if (!prs_set_offset(ps, data_offset))
		return False;

	/* And ensure we're 2 byte aligned. */

	if ( !prs_align_uint16(ps) )
		return False;

	return True;	
}

/*******************************************************************
 * write a structure.
 ********************************************************************/  

bool spoolss_io_r_enumprinterdataex(const char *desc, SPOOL_R_ENUMPRINTERDATAEX *r_u, prs_struct *ps, int depth)
{
	uint32 data_offset, end_offset;
	prs_debug(ps, depth, desc, "spoolss_io_r_enumprinterdataex");
	depth++;

	if(!prs_align(ps))
		return False;

	if (!prs_uint32("size", ps, depth, &r_u->ctr.size))
		return False;

	data_offset = prs_offset(ps);

	if (!prs_set_offset(ps, data_offset + r_u->ctr.size))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("needed",     ps, depth, &r_u->needed))
		return False;

	if(!prs_uint32("returned",   ps, depth, &r_u->returned))
		return False;

	if(!prs_werror("status",     ps, depth, &r_u->status))
		return False;

	r_u->ctr.size_of_array = r_u->returned;

	end_offset = prs_offset(ps);

	if (!prs_set_offset(ps, data_offset))
		return False;

	if (r_u->ctr.size)
		if (!spoolss_io_printer_enum_values_ctr("", ps, &r_u->ctr, depth ))
			return False;

	if (!prs_set_offset(ps, end_offset))
		return False;
	return True;
}
