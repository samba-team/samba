/* 
   Samba Unix/Linux SMB client library 
   net lookup command
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "includes.h"
#include "../utils/net.h"

int net_lookup_usage(int argc, const char **argv)
{
	d_printf(
"  net lookup host HOSTNAME <type>\n\tgives IP for a hostname\n\n"\
"\n");
	return -1;
}

/* lookup a hostname giving an IP */
static int net_lookup_host(int argc, const char **argv)
{
	struct in_addr ip;
	int name_type = 0x20;

	if (argc == 0) return net_lookup_usage(argc, argv);
	if (argc > 1) name_type = strtol(argv[1], NULL, 0);

	if (!resolve_name(argv[0], &ip, name_type)) {
		/* we deliberately use DEBUG() here to send it to stderr 
		   so scripts aren't mucked up */
		DEBUG(0,("Didn't find %s#%02x\n", argv[0], name_type));
		return -1;
	}

	d_printf("%s\n", inet_ntoa(ip));
	return 0;
}


/* lookup hosts or IP addresses using internal samba lookup fns */
int net_lookup(int argc, const char **argv)
{
	struct functable func[] = {
		{"HOST", net_lookup_host},
		{NULL, NULL}
	};

	return net_run_function(argc, argv, func, net_lookup_usage);
}
