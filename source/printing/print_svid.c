/*
 * Copyright (C) 1997-1998 by Norm Jacobs, Colorado Springs, Colorado, USA
 * Copyright (C) 1997-1998 by Sun Microsystem, Inc.
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This module implements support for gathering and comparing available
 * printer information on a SVID or XPG4 compliant system.  It does this
 * through the use of the SVID/XPG4 command "lpstat(1)".
 *
 * The expectations is that execution of the command "lpstat -v" will
 * generate responses in the form of:
 *
 *	device for serial: /dev/term/b
 *	system for fax: server
 *	system for color: server (as printer chroma)
 */


#include "includes.h"
#include "smb.h"

#ifdef SYSV

typedef struct printer {
	char *name;
	struct printer *next;
} printer_t;
static printer_t *printers = NULL;

static void populate_printers(void)
{
	char **lines;
	int i;

	lines = file_lines_pload("/usr/bin/lpstat -v", NULL, False);
	if (!lines) return;

	for (i=0;lines[i];i++) {
		printer_t *ptmp;
		char *name, *tmp;
		char *buf = lines[i];

		/* eat "system/device for " */
		if (((tmp = strchr(buf, ' ')) == NULL) ||
		    ((tmp = strchr(++tmp, ' ')) == NULL))
			continue;

		/*
		 * In case we're only at the "for ".
		 */

		if(!strncmp("for ",++tmp,4)) {
			tmp=strchr(tmp, ' ');
			tmp++;
		}

		/* Eat whitespace. */

		while(*tmp == ' ')
			++tmp;

		/*
		 * On HPUX there is an extra line that can be ignored.
		 * d.thibadeau 2001/08/09
		 */
		if(!strncmp("remote to",tmp,9))
			continue;

		name = tmp;

		/* truncate the ": ..." */
		if ((tmp = strchr(name, ':')) != NULL)
			*tmp = '\0';
		
		/* add it to the cache */
		if ((ptmp = malloc(sizeof (*ptmp))) != NULL) {
			ZERO_STRUCTP(ptmp);
			if((ptmp->name = strdup(name)) == NULL)
				DEBUG(0,("populate_printers: malloc fail in strdup !\n"));
			ptmp->next = printers;
			printers = ptmp;
		} else {
			DEBUG(0,("populate_printers: malloc fail for ptmp\n"));
		}
	}

	file_lines_free(lines);
}


/*
 * provide the equivalent of pcap_printer_fn() for SVID/XPG4 conforming
 * systems.  It was unclear why pcap_printer_fn() was tossing names longer
 * than 8 characters.  I suspect that its a protocol limit, but amazingly
 * names longer than 8 characters appear to work with my test
 * clients (Win95/NT).
 */
void sysv_printer_fn(void (*fn)(char *, char *))
{
	printer_t *tmp;

	if (printers == NULL)
		populate_printers();
	for (tmp = printers; tmp != NULL; tmp = tmp->next)
		(fn)(unix_to_dos_static(tmp->name), "");
}


/*
 * provide the equivalent of pcap_printername_ok() for SVID/XPG4 conforming
 * systems.
 */
int sysv_printername_ok(char *name)
{
	printer_t *tmp;

	if (printers == NULL)
		populate_printers();
	for (tmp = printers; tmp != NULL; tmp = tmp->next)
		if (strcmp(tmp->name, name) == 0)
			return (True);
	return (False);
}

#else
/* this keeps fussy compilers happy */
 void print_svid_dummy(void);
 void print_svid_dummy(void) {}
#endif
