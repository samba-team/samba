/* 
   Unix SMB/CIFS implementation.
   load printer lists
   Copyright (C) Andrew Tridgell 1992-2000
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "printing/pcap.h"
#include "printing/printer_list.h"
#include "printing/load.h"
#include "lib/param/loadparm.h"

/***************************************************************************
auto-load some homes and printer services
***************************************************************************/
static void add_auto_printers(void)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *p;
	int pnum = lp_servicenumber(PRINTERS_NAME);
	char *str;
	char *saveptr;
	char *auto_serv = NULL;

	if (pnum < 0)
		if (process_registry_service(PRINTERS_NAME))
			pnum = lp_servicenumber(PRINTERS_NAME);

	if (pnum < 0)
		return;

	auto_serv = lp_auto_services(talloc_tos(), lp_sub);
	str = SMB_STRDUP(auto_serv);
	TALLOC_FREE(auto_serv);
	if (str == NULL) {
		return;
	}

	for (p = strtok_r(str, LIST_SEP, &saveptr); p;
	     p = strtok_r(NULL, LIST_SEP, &saveptr)) {
		if (lp_servicenumber(p) >= 0)
			continue;
		
		if (printer_list_printername_exists(p))
			lp_add_printer(p, pnum);
	}

	SAFE_FREE(str);
}

/***************************************************************************
load automatic printer services from pre-populated pcap cache
***************************************************************************/
void load_printers(void)
{
	NTSTATUS status;

	if (!pcap_cache_loaded(NULL)) {
		return;
	}

	add_auto_printers();

	if (!lp_load_printers()) {
		return;
	}

	/*
	 * Do not add printers from pcap, if we don't have a [printers] share.
	 */
	if (lp_servicenumber(PRINTERS_NAME) < 0) {
		return;
	}

	status = printer_list_read_run_fn(lp_add_one_printer, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("printer_list_read_run_fn failed: %s\n",
			   nt_errstr(status));
	}
}

bool pcap_cache_loaded(time_t *_last_change)
{
	NTSTATUS status;
	time_t last;

	status = printer_list_get_last_refresh(&last);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	if (_last_change != NULL) {
		*_last_change = last;
	}
	return true;
}
