/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb utility functions
 *
 *  Description: miscellanous utility functions for ldb
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"


/*
  common code for parsing -o options in ldb tools
*/
const char **ldb_options_parse(const char **options, int *ldbopts, const char *arg)
{
	if (*ldbopts == 0) {
		options = malloc(sizeof(char *) * 2);
	} else {
		options = realloc(options, sizeof(char *)*((*ldbopts)+2));
	}
	if (options == NULL) {
		fprintf(stderr, "Out of memory in options parsing!\n");
		exit(-1);
	}
	options[(*ldbopts)++] = arg;
	options[*ldbopts] = NULL;
	return options;
}
