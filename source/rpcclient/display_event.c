/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1999
   
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


/****************************************************************************
 display structure
 ****************************************************************************/
void display_eventlog_eventrecord(FILE *out_hnd, enum action_type action, EVENTLOGRECORD *const ev)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			report(out_hnd, "\tevent log records\n"); 
			report(out_hnd, "\t-----------------\n");
			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring temp;
			report(out_hnd, "\t\trecord n.:\t%d\n", ev->recordnumber);
			
			report(out_hnd, "\t\tsource\teventnumber\teventtype\tcategory\n");
			unistr_to_ascii(temp, ev->sourcename.buffer, sizeof(temp)-1);
			
			report(out_hnd, "\t\t%s", temp);
			
			report(out_hnd, "\t%d\t\t", ev->eventnumber&0x0000FFFF);
			
			switch (ev->eventtype)
			{
				case EVENTLOG_OK:
					report(out_hnd, "Normal");
					break;
 
				case EVENTLOG_ERROR:
					report(out_hnd, "Error");
					break;
			
				case EVENTLOG_WARNING:
					report(out_hnd, "Warning");
					break;
			
				case EVENTLOG_INFORMATION:
					report(out_hnd, "Information");
					break;
			
				case EVENTLOG_AUDIT_OK:
					report(out_hnd, "Audit Normal");
					break;
			
				case EVENTLOG_AUDIT_ERROR:
					report(out_hnd, "Audit Error\n");
					break;			
			}
			
			report(out_hnd, "\t%d\n", ev->category);
			report(out_hnd, "\t\tcreationtime:\t%s\n", http_timestring(ev->creationtime));
			report(out_hnd, "\t\twritetime:\t%s\n", http_timestring(ev->writetime));

			unistr_to_ascii(temp, ev->computername.buffer, sizeof(temp)-1);
			report(out_hnd, "\t\tcomputer:\t%s\n", temp);

			if (ev->num_of_strings!=0)
			{
				unistr_to_ascii(temp, ev->strings.buffer, sizeof(temp)-1);
				report(out_hnd, "\t\tdescription:\t%s\n", temp);
			}

			report(out_hnd, "\n");			
			break;
		}
		case ACTION_FOOTER:
		{
			report(out_hnd, "\n");
			break;
		}
	}
}

