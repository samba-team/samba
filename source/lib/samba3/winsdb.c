/* 
   Unix SMB/CIFS implementation.
   Wins Database

   Copyright (C) Jeremy Allison 1994-2003
   Copyright (C) Jelmer Vernooij 2005

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
#include "system/filesys.h"
#include "lib/samba3/samba3.h"

#define WINS_VERSION 1

NTSTATUS samba3_read_winsdb( const char *fn, TALLOC_CTX *ctx, struct samba3_winsdb_entry **entries, uint32_t *count )
{
	XFILE *fp;
	char *line;

	if((fp = x_fopen(fn,O_RDONLY,0)) == NULL) {
		DEBUG(0,("initialise_wins: Can't open wins database file %s. Error was %s\n",
			fn, strerror(errno) ));
		return NT_STATUS_OPEN_FAILED;
	}

	*count = 0;
	*entries = NULL;

	while (!x_feof(fp)) {
		struct samba3_winsdb_entry entry;
		const char *name_str, *ttl_str, *nb_flags_str;
		const char **args;
		char *p;
		int i;
		unsigned int hash;
		int version;

		/* Read a line from the wins.dat file. Strips whitespace
			from the beginning and end of the line.  */
		line = fgets_slash(NULL,8,fp);
		if (!line) {
			return NT_STATUS_UNEXPECTED_IO_ERROR;
		}
      
		if (*line == '#') {
			SAFE_FREE(line);
			continue;
		}

		if (strncmp(line,"VERSION ", 8) == 0) {
			if (sscanf(line,"VERSION %d %u", &version, &hash) != 2 ||
						version != WINS_VERSION) {
				DEBUG(0,("Discarding invalid wins.dat file [%s]\n",line));
				SAFE_FREE(line);
				x_fclose(fp);
				return NT_STATUS_REVISION_MISMATCH;
			}
			SAFE_FREE(line);

			continue;
		}

		args = str_list_make_shell(ctx, line, NULL);

		/* 
		 * Now we handle multiple IP addresses per name we need
		 * to iterate over the line twice. The first time to
		 * determine how many IP addresses there are, the second
		 * time to actually parse them into the ip_list array.
		 */

		name_str = args[0];
		if (!name_str) {
			DEBUG(0,("initialise_wins: Failed to parse name when parsing line %s\n", line ));
			SAFE_FREE(line);
			continue;
		}

		ttl_str = args[1];
		if (!ttl_str) {
			DEBUG(0,("initialise_wins: Failed to parse time to live when parsing line %s\n", line ));
			SAFE_FREE(line);
			continue;
		}

		/*
		 * Determine the number of IP addresses per line.
		 */
		entry.ip_count = 0;
		for (i = 2; args[i] && strchr(args[i], '.'); i++) entry.ip_count++;

		if(entry.ip_count == 0) {
			DEBUG(0,("initialise_wins: Missing IP address when parsing line %s\n", line ));
			SAFE_FREE(line);
			continue;
		}

		/* Allocate the space for the ip_list. */
		if((entry.ips = talloc_array ( ctx, struct ipv4_addr, entry.ip_count)) == NULL) {
			DEBUG(0,("initialise_wins: Malloc fail !\n"));
			SAFE_FREE(line);
			return NT_STATUS_NO_MEMORY;
		}
 
		/* Reset and re-parse the line. */
		for(i = 0; i < entry.ip_count; i++) {
			entry.ips[i] = interpret_addr2(args[i+2]);
		}
		nb_flags_str = args[2 + entry.ip_count];

		SMB_ASSERT(nb_flags_str);

		/* 
		 * Deal with SELF or REGISTER name encoding. Default is REGISTER
		 * for compatibility with old nmbds.
		 */

		if(nb_flags_str[strlen(nb_flags_str)-1] == 'S') {
			DEBUG(5,("initialise_wins: Ignoring SELF name %s\n", line));
			talloc_free(entry.ips);
			SAFE_FREE(line);
			continue;
		}
      
		/* Netbios name. # divides the name from the type (hex): netbios#xx */
		entry.name = talloc_strdup(ctx, name_str);
      
		if((p = strchr(entry.name,'#')) != NULL) {
			*p = 0;
			sscanf(p+1,"%x",&entry.type);
		}
      
		/* Decode the netbios flags (hex) and the time-to-live (in seconds). */
		sscanf(nb_flags_str,"%x",&entry.nb_flags);
		entry.ttl = atol(ttl_str);

		*entries = talloc_realloc(ctx, *entries, struct samba3_winsdb_entry, (*count)+1);
		(*entries)[*count] = entry;

		(*count)++;
	} 
    
	x_fclose(fp);
	return NT_STATUS_OK;
}
