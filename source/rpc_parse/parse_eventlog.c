/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
 *  Copyright (C) Jean François Micouleau      1998-1999.
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

extern int DEBUGLEVEL;

/*******************************************************************
********************************************************************/  
BOOL make_eventlog_q_open(EVENTLOG_Q_OPEN *q_u, const char *journal, char *unk)
{
	int len_journal = journal != NULL ? strlen(journal) : 0;
	int len_unk = unk != NULL ? strlen(unk) : 0;

	q_u->ptr0=0x1;
	q_u->unk0=0x5c;
	q_u->unk1=0x01;

	make_uni_hdr(&(q_u->hdr_source), len_journal);
	make_unistr2(&(q_u->uni_source), journal, len_journal);
	
	make_uni_hdr(&(q_u->hdr_unk), len_unk);
	make_unistr2(&(q_u->uni_unk), unk, len_unk);
	
	q_u->unk6=0x01; /* one of these is an access mask! */
	q_u->unk7=0x01; /* one of these is an access mask! */

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL eventlog_io_q_open(char *desc, EVENTLOG_Q_OPEN *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "eventlog_io_q_open");
	depth++;

	prs_align(ps);

	prs_uint32("ptr0", ps, depth, &(q_u->ptr0));

	prs_uint16("unk0", ps, depth, &(q_u->unk0));
	prs_uint16("unk1", ps, depth, &(q_u->unk1));

	smb_io_unihdr("hdr_source", &(q_u->hdr_source), ps, depth);
	smb_io_unistr2("uni_source", &(q_u->uni_source),
		       q_u->hdr_source.buffer, ps, depth);
	prs_align(ps);

	smb_io_unihdr("hdr_unk", &(q_u->hdr_unk), ps, depth);
	smb_io_unistr2("uni_unk", &(q_u->uni_unk),
		       q_u->hdr_unk.buffer, ps, depth);
	prs_align(ps);

	prs_uint32("unk6", ps, depth, &(q_u->unk6));
	prs_uint32("unk7", ps, depth, &(q_u->unk7));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL eventlog_io_r_open(char *desc, EVENTLOG_R_OPEN *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "eventlog_io_r_open");
	depth++;

	prs_align(ps);
	smb_io_pol_hnd("", &(r_u->pol), ps, depth);
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL make_eventlog_q_close(EVENTLOG_Q_CLOSE *q_u, POLICY_HND *pol)
{
	if ((q_u == NULL) || (pol == NULL))
	{
		return False;
	}

	q_u->pol = *pol;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL eventlog_io_q_close(char *desc, EVENTLOG_Q_CLOSE *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "eventlog_io_q_close");
	depth++;

	prs_align(ps);
	smb_io_pol_hnd("", &(q_u->pol), ps, depth);

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL eventlog_io_r_close(char *desc, EVENTLOG_R_CLOSE *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "eventlog_io_r_close");
	depth++;

	prs_align(ps);
	smb_io_pol_hnd("", &(r_u->pol), ps, depth);
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL make_eventlog_q_numofeventlogrec(EVENTLOG_Q_NUMOFEVENTLOGREC *q_u, POLICY_HND *pol)
{
	if ((q_u == NULL) || (pol == NULL))
	{
		return False;
	}

	q_u->pol = *pol;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL eventlog_io_q_numofeventlogrec(char *desc,EVENTLOG_Q_NUMOFEVENTLOGREC  *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "eventlog_io_q_numofeventlogrec");
	depth++;

	prs_align(ps);
	smb_io_pol_hnd("", &(q_u->pol), ps, depth);

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL eventlog_io_r_numofeventlogrec(char *desc, EVENTLOG_R_NUMOFEVENTLOGREC *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "eventlog_io_r_numofeventlogrec");
	depth++;

	prs_align(ps);
	prs_uint32("number", ps, depth, &(r_u->number));
	prs_uint32("status", ps, depth, &(r_u->status));

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL make_eventlog_q_readeventlog(EVENTLOG_Q_READEVENTLOG *q_u, POLICY_HND *pol,
                                  uint32 flags, uint32 offset, uint32 number_of_bytes)
{
	if ((q_u == NULL) || (pol == NULL))
	{
		return False;
	}

	q_u->pol = *pol;
	q_u->flags = flags;
	q_u->offset = offset;
	q_u->number_of_bytes = number_of_bytes;

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL eventlog_io_q_readeventlog(char *desc, EVENTLOG_Q_READEVENTLOG *q_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "eventlog_io_q_readeventlog");
	depth++;

	prs_align(ps);
	smb_io_pol_hnd("", &(q_u->pol), ps, depth);
	prs_uint32("flags",           ps, depth, &(q_u->flags));
	prs_uint32("offset",          ps, depth, &(q_u->offset));
	prs_uint32("number_of_bytes", ps, depth, &(q_u->number_of_bytes));

	return True;
}

/*******************************************************************
********************************************************************/  
static BOOL eventlog_io_eventlog(char *desc, EVENTLOGRECORD *ev, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "eventlog_io_eventlog");
	depth++;

	prs_align(ps);
	prs_uint32("size", ps, depth, &(ev->size));	
	prs_uint32("reserved", ps, depth, &(ev->reserved));
	prs_uint32("recordnumber", ps, depth, &(ev->recordnumber));
	prs_uint32("creationtime", ps, depth, &(ev->creationtime));
	prs_uint32("writetime", ps, depth, &(ev->writetime));
	prs_uint32("eventnumber", ps, depth, &(ev->eventnumber));
	
	prs_uint16("eventtype", ps, depth, &(ev->eventtype));
	prs_uint16("num_of_strings", ps, depth, &(ev->num_of_strings));
	prs_uint16("category", ps, depth, &(ev->category));
	prs_uint16("reserved_flag", ps, depth, &(ev->reserved_flag));

	prs_uint32("closingrecord", ps, depth, &(ev->closingrecord));
	prs_uint32("stringoffset", ps, depth, &(ev->stringoffset));
	prs_uint32("sid_length", ps, depth, &(ev->sid_length));
	prs_uint32("sid_offset", ps, depth, &(ev->sid_offset));
	prs_uint32("data_length", ps, depth, &(ev->data_length));
	prs_uint32("data_offset", ps, depth, &(ev->data_offset));
	
	smb_io_unistr("", &(ev->sourcename), ps, depth);	
	smb_io_unistr("", &(ev->computername), ps, depth);
	
	if (ev->sid_length!=0)
		smb_io_unistr("", &(ev->sid), ps, depth);
	
	if (ev->num_of_strings!=0)
		smb_io_unistr("", &(ev->strings),ps, depth);
	
	if (ev->data_length)
		smb_io_unistr("", &(ev->data), ps, depth);

	prs_uint32("size2", ps, depth, &(ev->size2));	

	return True;
}

/*******************************************************************
********************************************************************/  
BOOL eventlog_io_r_readeventlog(char *desc, EVENTLOG_R_READEVENTLOG *r_u, prs_struct *ps, int depth)
{
	prs_debug(ps, depth, desc, "eventlog_io_r_readeventlog");
	depth++;

	prs_align(ps);
	prs_uint32("number_of_bytes", ps, depth, &(r_u->number_of_bytes));

	if (r_u->number_of_bytes!= 0)
		eventlog_io_eventlog("", r_u->event, ps, depth);

	prs_uint32("sent_size", ps, depth, &(r_u->sent_size));		
	prs_uint32("real_size", ps, depth, &(r_u->real_size));
	prs_uint32("status", ps, depth, &(r_u->status));	

	return True;
}

