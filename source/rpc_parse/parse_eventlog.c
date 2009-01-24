/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Marcin Krzysztof Porwit    2005.
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

/********************************************************************
********************************************************************/

bool eventlog_io_q_read_eventlog(const char *desc, EVENTLOG_Q_READ_EVENTLOG *q_u,
				 prs_struct *ps, int depth)
{
	if(q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "eventlog_io_q_read_eventlog");
	depth++;

	if(!(prs_align(ps)))
		return False;

	if(!(smb_io_pol_hnd("log handle", &(q_u->handle), ps, depth)))
		return False;

	if(!(prs_uint32("read flags", ps, depth, &(q_u->flags))))
		return False;

	if(!(prs_uint32("read offset", ps, depth, &(q_u->offset))))
		return False;

	if(!(prs_uint32("read buf size", ps, depth, &(q_u->max_read_size))))
		return False;

	return True;
}
/** Structure of response seems to be:
   DWORD num_bytes_in_resp -- MUST be the same as q_u->max_read_size
   for i=0..n
       EVENTLOGRECORD record
   DWORD sent_size -- sum of EVENTLOGRECORD lengths if records returned, 0 otherwise
   DWORD real_size -- 0 if records returned, otherwise length of next record to be returned
   WERROR status */
bool eventlog_io_r_read_eventlog(const char *desc,
				 EVENTLOG_Q_READ_EVENTLOG *q_u,
				 EVENTLOG_R_READ_EVENTLOG *r_u,
				 prs_struct *ps,
				 int depth)
{
	Eventlog_entry *entry;
	uint32 record_written = 0;
	uint32 record_total = 0;

	if(r_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "eventlog_io_r_read_eventlog");
	depth++;

	/* First, see if we've read more logs than we can output */

	if(r_u->num_bytes_in_resp > q_u->max_read_size) {
		entry = r_u->entry;

		/* remove the size of the last entry from the list */

		while(entry->next != NULL)
			entry = entry->next;

		r_u->num_bytes_in_resp -= entry->record.length;

		/* do not output the last log entry */
	
		r_u->num_records--;
	}
    
	entry = r_u->entry;
	record_total = r_u->num_records;

	if(r_u->num_bytes_in_resp != 0)
		r_u->sent_size = r_u->num_bytes_in_resp;
	else
		r_u->real_size = r_u->bytes_in_next_record;

	if(!(prs_align(ps)))
		return False;
	if(!(prs_uint32("bytes in resp", ps, depth, &(q_u->max_read_size))))
		return False;

	while(entry != NULL && record_written < record_total)
	{
		DEBUG(11, ("eventlog_io_r_read_eventlog: writing record [%d] out of [%d].\n", record_written, record_total));

		/* Encode the actual eventlog record record */

		if(!(prs_uint32("length", ps, depth, &(entry->record.length))))
			return False;
		if(!(prs_uint32("reserved", ps, depth, &(entry->record.reserved1))))
			return False;
		if(!(prs_uint32("record number", ps, depth, &(entry->record.record_number))))
			return False;
		if(!(prs_uint32("time generated", ps, depth, &(entry->record.time_generated))))
			return False;
		if(!(prs_uint32("time written", ps, depth, &(entry->record.time_written))))
			return False;
		if(!(prs_uint32("event id", ps, depth, &(entry->record.event_id))))
			return False;
		if(!(prs_uint16("event type", ps, depth, &(entry->record.event_type))))
			return False;
		if(!(prs_uint16("num strings", ps, depth, &(entry->record.num_strings))))
			return False;
		if(!(prs_uint16("event category", ps, depth, &(entry->record.event_category))))
			return False;
		if(!(prs_uint16("reserved2", ps, depth, &(entry->record.reserved2))))
			return False;
		if(!(prs_uint32("closing record", ps, depth, &(entry->record.closing_record_number))))
			return False;
		if(!(prs_uint32("string offset", ps, depth, &(entry->record.string_offset))))
			return False;
		if(!(prs_uint32("user sid length", ps, depth, &(entry->record.user_sid_length))))
			return False;
		if(!(prs_uint32("user sid offset", ps, depth, &(entry->record.user_sid_offset))))
			return False;
		if(!(prs_uint32("data length", ps, depth, &(entry->record.data_length))))
			return False;
		if(!(prs_uint32("data offset", ps, depth, &(entry->record.data_offset))))
			return False;
		if(!(prs_align(ps)))
			return False;
	
		/* Now encoding data */

		if(!(prs_uint8s(False, "buffer", ps, depth, entry->data, 
			entry->record.length - sizeof(Eventlog_record) - sizeof(entry->record.length))))
		{
			return False;
		}

		if(!(prs_align(ps)))
			return False;
		if(!(prs_uint32("length 2", ps, depth, &(entry->record.length))))
			return False;

		entry = entry->next;
		record_written++;

	} 	/* end of encoding EVENTLOGRECORD */

	/* Now pad with whitespace until the end of the response buffer */

	if (q_u->max_read_size - r_u->num_bytes_in_resp) {
		r_u->end_of_entries_padding = PRS_ALLOC_MEM(ps, uint8_t, q_u->max_read_size - r_u->num_bytes_in_resp);
		if (!r_u->end_of_entries_padding) {
			return False;
		}

		if(!(prs_uint8s(False, "end of entries padding", ps, 
				depth, r_u->end_of_entries_padding,
				(q_u->max_read_size - r_u->num_bytes_in_resp)))) {
			return False;
		}
	}

	/* We had better be DWORD aligned here */

	if(!(prs_uint32("sent size", ps, depth, &(r_u->sent_size))))
		return False;
	if(!(prs_uint32("real size", ps, depth, &(r_u->real_size))))
		return False;
	if(!(prs_ntstatus("status code", ps, depth, &r_u->status)))
		return False;

	return True;
}
