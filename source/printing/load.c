/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   load printer lists
   Copyright (C) Andrew Tridgell 1992-2000
   
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


/***************************************************************************
auto-load printer services
***************************************************************************/
void add_all_printers(void)
{
	int printers = lp_servicenumber(PRINTERS_NAME);

	if (printers < 0) return;

	pcap_printer_fn(lp_add_one_printer);
}

/***************************************************************************
auto-load some homes and printer services
***************************************************************************/
static void add_auto_printers(void)
{
	char *p;
	int printers;
	char *str = strdup(lp_auto_services());

	if (!str) return;

	printers = lp_servicenumber(PRINTERS_NAME);

	if (printers < 0) {
        SAFE_FREE(str);
        return;
    }
	
	for (p=strtok(str,LIST_SEP);p;p=strtok(NULL,LIST_SEP)) {
		if (lp_servicenumber(p) >= 0) continue;
		
		if (pcap_printername_ok(p,NULL)) {
			lp_add_printer(p,printers);
		}
	}

    SAFE_FREE(str);
}

/***************************************************************************
load automatic printer services
***************************************************************************/
void load_printers(void)
{
	add_auto_printers();
	if (lp_load_printers())
		add_all_printers();
}
