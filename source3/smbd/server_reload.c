/*
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Andrew Tridgell		1992-1998
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002-2003
   Copyright (C) Volker Lendecke		1993-2007
   Copyright (C) Jeremy Allison			1993-2007

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "nt_printing.h"
#include "printing/pcap.h"
#include "printing/load.h"
#include "auth.h"
#include "messages.h"
#include "lib/param/loadparm.h"

/*
 * The persistent pcap cache is populated by the background print process. Per
 * client smbds should only reload their printer share inventories if this
 * information has changed. Use reload_last_pcap_time to detect this.
 */
static time_t reload_last_pcap_time = 0;

bool snum_is_shared_printer(int snum)
{
	return (lp_browseable(snum) && lp_snum_ok(snum) && lp_printable(snum));
}

/**
 * @brief Purge stale printer shares and reload from pre-populated pcap cache.
 *
 * This function should normally only be called as a callback on a successful
 * pcap_cache_reload(), or on client enumeration.
 */
void delete_and_reload_printers(void)
{
	int n_services;
	int pnum;
	int snum;
	const char *pname;
	bool ok;
	time_t pcap_last_update;
	TALLOC_CTX *frame = talloc_stackframe();
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	ok = pcap_cache_loaded(&pcap_last_update);
	if (!ok) {
		DEBUG(1, ("pcap cache not loaded\n"));
		talloc_free(frame);
		return;
	}

	if (reload_last_pcap_time == pcap_last_update) {
		DEBUG(5, ("skipping printer reload, already up to date.\n"));
		talloc_free(frame);
		return;
	}
	reload_last_pcap_time = pcap_last_update;

	/* Get pcap printers updated */
	load_printers();

	n_services = lp_numservices();
	pnum = lp_servicenumber(PRINTERS_NAME);

	DEBUG(10, ("reloading printer services from pcap cache\n"));

	/*
	 * Add default config for printers added to smb.conf file and remove
	 * stale printers
	 */
	for (snum = 0; snum < n_services; snum++) {
		/* avoid removing PRINTERS_NAME */
		if (snum == pnum) {
			continue;
		}

		/* skip no-printer services */
		if (!snum_is_shared_printer(snum)) {
			continue;
		}

		pname = lp_printername(frame, lp_sub, snum);

		/* check printer, but avoid removing non-autoloaded printers */
		if (lp_autoloaded(snum) && !pcap_printername_ok(pname)) {
			lp_killservice(snum);
		}
	}

	/* Make sure deleted printers are gone */
	load_printers();

	talloc_free(frame);
}

/****************************************************************************
 Reload the services file.
**************************************************************************/

bool reload_services(struct smbd_server_connection *sconn,
		     bool (*snumused) (struct smbd_server_connection *, int),
		     bool test)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct smbXsrv_connection *xconn = NULL;
	bool ret;

	if (lp_loaded()) {
		char *fname = lp_next_configfile(talloc_tos(), lp_sub);
		if (file_exist(fname) &&
		    !strcsequal(fname, get_dyn_CONFIGFILE())) {
			set_dyn_CONFIGFILE(fname);
			test = False;
		}
		TALLOC_FREE(fname);
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return(True);

	lp_killunused(sconn, snumused);

	ret = lp_load_with_shares(get_dyn_CONFIGFILE());

	/* perhaps the config filename is now set */
	if (!test) {
		reload_services(sconn, snumused, true);
	}

	reopen_logs();

	load_interfaces();

	if (sconn != NULL && sconn->client != NULL) {
		xconn = sconn->client->connections;
	}
	for (;xconn != NULL; xconn = xconn->next) {
		set_socket_options(xconn->transport.sock, "SO_KEEPALIVE");
		set_socket_options(xconn->transport.sock, lp_socket_options());
	}

	mangle_reset_cache();
	reset_stat_cache();
	flush_dfree_cache();

	return(ret);
}
