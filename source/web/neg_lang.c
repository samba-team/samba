/*
   Unix SMB/CIFS implementation.
   SWAT language handling
   
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

   Created by Ryo Kawahara <rkawa@lbe.co.jp> 
*/

#include "includes.h"

/*
  during a file download we first check to see if there is a language
  specific file available. If there is then use that, otherwise 
  just open the specified file
*/
int web_open(const char *fname, int flags, mode_t mode)
{
	char *p = NULL;
	char *lang = lang_tdb_current();
	int fd;
	if (lang) {
		asprintf(&p, "lang/%s/%s", lang, fname);
		if (p) {
			fd = sys_open(p, flags, mode);
			free(p);
			if (fd != -1) {
				return fd;
			}
		}
	}

	/* fall through to default name */
	return sys_open(fname, flags, mode);
}


/*
  choose from a list of languages. The list can be comma or space
  separated
  Keep choosing until we get a hit 
*/
void web_set_lang(const char *lang_list)
{
	fstring lang;
	char *p = (char *)lang_list;
	
	while (next_token(&p, lang, ", \t\r\n", sizeof(lang))) {
		if (lang_tdb_init(lang)) return;
	}
	
	/* it's not an error to not initialise - we just fall back to 
	   the default */
}
