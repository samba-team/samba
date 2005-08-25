/* 
   Unix SMB/CIFS implementation.
   Wins Database

   Copyright (C) Jeremy Allison 1994-2003
   Copyright (C) Jelmer Vernooij 2005

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
#include "system/filesys.h"
#include "pstring.h"
#include "lib/samba3/samba3.h"

#define WINS_VERSION 1

NTSTATUS samba3_read_winsdb( const char *fn, TALLOC_CTX *ctx, struct samba3_winsdb_entry **entries, uint32_t *count )
{
	XFILE *fp;
	char *line;

	if((fp = x_fopen(fn,O_RDONLY,0)) == NULL) {
		DEBUG(0,("initialise_wins: Can't open wins database file %s. Error was %s\n",
			fn, strerror(errno) ));
		return NT_STATUS_UNSUCCESSFUL;
	}

	*count = 0;
	*entries = NULL;

	while (!x_feof(fp)) {
		struct samba3_winsdb_entry entry;
		pstring name_str, ip_str, ttl_str, nb_flags_str;
		const char *ptr;
		char *p;
		BOOL got_token;
		BOOL was_ip;
		int i;
		unsigned int hash;
		int version;

		/* Read a line from the wins.dat file. Strips whitespace
			from the beginning and end of the line.  */
		line = fgets_slash(NULL,8,fp);
		if (!line) 
			return NT_STATUS_UNSUCCESSFUL;
      
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
				return NT_STATUS_UNSUCCESSFUL;
			}
			SAFE_FREE(line);

			continue;
		}

		ptr = line;

		/* 
		 * Now we handle multiple IP addresses per name we need
		 * to iterate over the line twice. The first time to
		 * determine how many IP addresses there are, the second
		 * time to actually parse them into the ip_list array.
		 */

		if (!next_token(&ptr,name_str,NULL,sizeof(name_str))) {
			DEBUG(0,("initialise_wins: Failed to parse name when parsing line %s\n", line ));
			SAFE_FREE(line);
			continue;
		}

		if (!next_token(&ptr,ttl_str,NULL,sizeof(ttl_str))) {
			DEBUG(0,("initialise_wins: Failed to parse time to live when parsing line %s\n", line ));
			SAFE_FREE(line);
			continue;
		}

		/*
		 * Determine the number of IP addresses per line.
		 */
		entry.ip_count = 0;
		do {
			got_token = next_token(&ptr,ip_str,NULL,sizeof(ip_str));
			was_ip = False;

			if(got_token && strchr(ip_str, '.')) {
				entry.ip_count++;
				was_ip = True;
			}
		} while( got_token && was_ip);

		if(entry.ip_count == 0) {
			DEBUG(0,("initialise_wins: Missing IP address when parsing line %s\n", line ));
			SAFE_FREE(line);
			continue;
		}

		if(!got_token) {
			DEBUG(0,("initialise_wins: Missing nb_flags when parsing line %s\n", line ));
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
		ptr = line;
		next_token(&ptr,name_str,NULL,sizeof(name_str)); 
		next_token(&ptr,ttl_str,NULL,sizeof(ttl_str));
		for(i = 0; i < entry.ip_count; i++) {
			next_token(&ptr, ip_str, NULL, sizeof(ip_str));
			entry.ips[i] = interpret_addr2(ip_str);
		}
		next_token(&ptr,nb_flags_str,NULL, sizeof(nb_flags_str));

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
      
		if(nb_flags_str[strlen(nb_flags_str)-1] == 'R')
			nb_flags_str[strlen(nb_flags_str)-1] = '\0';
      
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
