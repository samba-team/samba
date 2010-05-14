/* 
   Unix SMB/CIFS implementation.
   printcap parsing
   Copyright (C) Karl Auer 1993-1998

   Re-working by Martin Kiff, 1994
   
   Re-written again by Andrew Tridgell

   Modified for SVID support by Norm Jacobs, 1997

   Modified for CUPS support by Michael Sweet, 1999
   
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

/*
 *  Modified to call SVID/XPG4 support if printcap name is set to "lpstat"
 *  in smb.conf under Solaris.
 *
 *  Modified to call CUPS support if printcap name is set to "cups"
 *  in smb.conf.
 *
 *  Modified to call iPrint support if printcap name is set to "iprint"
 *  in smb.conf.
 */

#include "includes.h"
#include "printing/pcap.h"

struct pcap_cache {
	char *name;
	char *comment;
	struct pcap_cache *next;
};

/* The systemwide printcap cache. */
static struct pcap_cache *pcap_cache = NULL;

bool pcap_cache_add_specific(struct pcap_cache **ppcache, const char *name, const char *comment)
{
	struct pcap_cache *p;

	if (name == NULL || ((p = SMB_MALLOC_P(struct pcap_cache)) == NULL))
		return false;

	p->name = SMB_STRDUP(name);
	p->comment = (comment && *comment) ? SMB_STRDUP(comment) : NULL;

	DEBUG(11,("pcap_cache_add_specific: Adding name %s info %s\n",
		p->name, p->comment ? p->comment : ""));

	p->next = *ppcache;
	*ppcache = p;

	return true;
}

void pcap_cache_destroy_specific(struct pcap_cache **pp_cache)
{
	struct pcap_cache *p, *next;

	for (p = *pp_cache; p != NULL; p = next) {
		next = p->next;

		SAFE_FREE(p->name);
		SAFE_FREE(p->comment);
		SAFE_FREE(p);
	}
	*pp_cache = NULL;
}

bool pcap_cache_add(const char *name, const char *comment)
{
	return pcap_cache_add_specific(&pcap_cache, name, comment);
}

bool pcap_cache_loaded(void)
{
	return (pcap_cache != NULL);
}

void pcap_cache_replace(const struct pcap_cache *pcache)
{
	const struct pcap_cache *p;

	pcap_cache_destroy_specific(&pcap_cache);
	for (p = pcache; p; p = p->next) {
		pcap_cache_add(p->name, p->comment);
	}
}

void pcap_cache_reload(void)
{
	const char *pcap_name = lp_printcapname();
	bool pcap_reloaded = False;
	struct pcap_cache *tmp_cache = NULL;

	DEBUG(3, ("reloading printcap cache\n"));

	/* only go looking if no printcap name supplied */
	if (pcap_name == NULL || *pcap_name == 0) {
		DEBUG(0, ("No printcap file name configured!\n"));
		return;
	}

	tmp_cache = pcap_cache;
	pcap_cache = NULL;

#ifdef HAVE_CUPS
	if (strequal(pcap_name, "cups")) {
		pcap_reloaded = cups_cache_reload();
		goto done;
	}
#endif

#ifdef HAVE_IPRINT
	if (strequal(pcap_name, "iprint")) {
		pcap_reloaded = iprint_cache_reload();
		goto done;
	}
#endif

#if defined(SYSV) || defined(HPUX)
	if (strequal(pcap_name, "lpstat")) {
		pcap_reloaded = sysv_cache_reload();
		goto done;
	}
#endif

#ifdef AIX
	if (strstr_m(pcap_name, "/qconfig") != NULL) {
		pcap_reloaded = aix_cache_reload();
		goto done;
	}
#endif

	pcap_reloaded = std_pcap_cache_reload(pcap_name);

done:
	DEBUG(3, ("reload status: %s\n", (pcap_reloaded) ? "ok" : "error"));

	if (pcap_reloaded)
		pcap_cache_destroy_specific(&tmp_cache);
	else {
		pcap_cache_destroy_specific(&pcap_cache);
		pcap_cache = tmp_cache;
	}

	return;
}


bool pcap_printername_ok(const char *printername)
{
	struct pcap_cache *p;

	for (p = pcap_cache; p != NULL; p = p->next)
		if (strequal(p->name, printername))
			return True;

	return False;
}

/***************************************************************************
run a function on each printer name in the printcap file.
***************************************************************************/

void pcap_printer_fn_specific(const struct pcap_cache *pc,
			void (*fn)(const char *, const char *, void *),
			void *pdata)
{
	const struct pcap_cache *p;

	for (p = pc; p != NULL; p = p->next)
		fn(p->name, p->comment, pdata);

	return;
}

void pcap_printer_fn(void (*fn)(const char *, const char *, void *), void *pdata)
{
	pcap_printer_fn_specific(pcap_cache, fn, pdata);
}
