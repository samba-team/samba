/* 
   Unix SMB/CIFS implementation.
   filename matching routine
   Copyright (C) Andrew Tridgell 1992-1998 

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

/*
   This module was originally based on fnmatch.c copyright by the Free
   Software Foundation. It bears little resemblence to that code now 
*/  


#if FNMATCH_TEST
#include <stdio.h>
#include <stdlib.h>
#else
#include "includes.h"
#endif

/* 
   bugger. we need a separate wildcard routine for older versions
   of the protocol. This is not yet perfect, but its a lot
   better than what we had */
static int ms_fnmatch_lanman_core(const smb_ucs2_t *pattern, 
				  const smb_ucs2_t *string)
{
	const smb_ucs2_t *p = pattern, *n = string;
	smb_ucs2_t c;

	if (strcmp_wa(p, "?")==0 && strcmp_wa(n, ".")) goto match;

	while ((c = *p++)) {
		switch (c) {
		case UCS2_CHAR('.'):
			if (! *n) goto next;
			if (*n != UCS2_CHAR('.')) goto nomatch;
			n++;
			break;

		case UCS2_CHAR('?'):
			if (! *n) goto next;
			if ((*n == UCS2_CHAR('.') && 
			     n[1] != UCS2_CHAR('.')) || ! *n) 
				goto next;
			n++;
			break;

		case UCS2_CHAR('>'):
			if (! *n) goto next;
			if (n[0] == UCS2_CHAR('.')) {
				if (! n[1] && ms_fnmatch_lanman_core(p, n+1) == 0) goto match;
				if (ms_fnmatch_lanman_core(p, n) == 0) goto match;
				goto nomatch;
			}
			n++;
			break;

		case UCS2_CHAR('*'):
			if (! *n) goto next;
			if (! *p) goto match;
			for (; *n; n++) {
				if (ms_fnmatch_lanman_core(p, n) == 0) goto match;
			}
			break;

		case UCS2_CHAR('<'):
			for (; *n; n++) {
				if (ms_fnmatch_lanman_core(p, n) == 0) goto match;
				if (*n == UCS2_CHAR('.') && 
				    !strchr_w(n+1,UCS2_CHAR('.'))) {
					n++;
					break;
				}
			}
			break;

		case UCS2_CHAR('"'):
			if (*n == 0 && ms_fnmatch_lanman_core(p, n) == 0) goto match;
			if (*n != UCS2_CHAR('.')) goto nomatch;
			n++;
			break;

		default:
			if (c != *n &&
			    toupper_w(c) != toupper_w(*n)) goto nomatch;
			n++;
		}
	}
	
	if (! *n) goto match;
	
 nomatch:
	/*
	if (verbose) printf("NOMATCH pattern=[%s] string=[%s]\n", pattern, string);
	*/
	return -1;

next:
	if (ms_fnmatch_lanman_core(p, n) == 0) goto match;
        goto nomatch;

 match:
	/*
	if (verbose) printf("MATCH   pattern=[%s] string=[%s]\n", pattern, string);
	*/
	return 0;
}

static int ms_fnmatch_lanman1(const smb_ucs2_t *pattern, const smb_ucs2_t *string)
{
	if (!strpbrk_wa(pattern, "?*<>\"")) {
		smb_ucs2_t s[] = {UCS2_CHAR('.'), 0};
		if (strcmp_wa(string,"..") == 0) string = s;
		return strcasecmp_w(pattern, string);
	}

	if (strcmp_wa(string,"..") == 0 || strcmp_wa(string,".") == 0) {
		smb_ucs2_t dot[] = {UCS2_CHAR('.'), 0};
		smb_ucs2_t dotdot[] = {UCS2_CHAR('.'), UCS2_CHAR('.'), 0};
		return ms_fnmatch_lanman_core(pattern, dotdot) &&
			ms_fnmatch_lanman_core(pattern, dot);
	}

	return ms_fnmatch_lanman_core(pattern, string);
}


/* the following function was derived using the masktest utility -
   after years of effort we finally have a perfect MS wildcard
   matching routine! 

   NOTE: this matches only filenames with no directory component

   Returns 0 on match, -1 on fail.
*/
static int ms_fnmatch_w(const smb_ucs2_t *pattern, const smb_ucs2_t *string, 
			enum protocol_types protocol)
{
	const smb_ucs2_t *p = pattern, *n = string;
	smb_ucs2_t c;

	if (protocol <= PROTOCOL_LANMAN2) {
		return ms_fnmatch_lanman1(pattern, string);
	}

	while ((c = *p++)) {
		switch (c) {
		case UCS2_CHAR('?'):
			if (! *n) return -1;
			n++;
			break;

		case UCS2_CHAR('>'):
			if (n[0] == UCS2_CHAR('.')) {
				if (! n[1] && ms_fnmatch_w(p, n+1, protocol) == 0) return 0;
				if (ms_fnmatch_w(p, n, protocol) == 0) return 0;
				return -1;
			}
			if (! *n) return ms_fnmatch_w(p, n, protocol);
			n++;
			break;

		case UCS2_CHAR('*'):
			while (*p == UCS2_CHAR('*')) {
				p++;
			}
			for (; *n; n++) {
				if (ms_fnmatch_w(p, n, protocol) == 0) return 0;
			}
			break;

		case UCS2_CHAR('<'):
			for (; *n; n++) {
				if (ms_fnmatch_w(p, n, protocol) == 0) return 0;
				if (*n == UCS2_CHAR('.') && !strchr_wa(n+1,'.')) {
					n++;
					break;
				}
			}
			break;

		case UCS2_CHAR('"'):
			if (*n == 0 && ms_fnmatch_w(p, n, protocol) == 0) return 0;
			if (*n != UCS2_CHAR('.')) return -1;
			n++;
			break;

		default:
			if (c != *n &&
			    toupper_w(c) != toupper_w(*n)) return -1;
			n++;
		}
	}
	
	if (! *n) return 0;
	
	return -1;
}


int ms_fnmatch(const char *pattern, const char *string, enum protocol_types protocol)
{
	wpstring p, s;
	int ret;

	pstrcpy_wa(p, pattern);
	pstrcpy_wa(s, string);

	ret = ms_fnmatch_w(p, s, protocol);
/* 	DEBUG(0,("ms_fnmatch(%s,%s) -> %d\n", pattern, string, ret)); */
	return ret;
}

/* a generic fnmatch function - uses for non-CIFS pattern matching */
int gen_fnmatch(const char *pattern, const char *string)
{
	return ms_fnmatch(pattern, string, PROTOCOL_NT1);
}
