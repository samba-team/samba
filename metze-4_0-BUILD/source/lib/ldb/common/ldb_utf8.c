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
 *  Component: ldb utf8 handling
 *
 *  Description: case folding and case comparison for UTF8 strings
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"

/*
  TODO:
  a simple case folding function - will be replaced by a UTF8 aware function later
*/
char *ldb_casefold(struct ldb_context *ldb, const char *s)
{
	int i;
	char *ret = ldb_strdup(ldb, s);
	if (!s) {
		errno = ENOMEM;
		return NULL;
	}
	for (i=0;ret[i];i++) {
		ret[i] = toupper(ret[i]);
	}
	return ret;
}

/*
  a caseless compare, optimised for 7 bit
  TODO: doesn't yet handle UTF8
*/
static int ldb_caseless_cmp(const char *s1, const char *s2)
{
	int i;
	for (i=0;s1[i] != 0;i++) {
		int c1 = toupper(s1[i]), c2 = toupper(s2[i]);
		if (c1 != c2) {
			return c1 - c2;
		}
	}
	return s2[i];
}

/*
  compare two basedn fields
  return 0 for match
*/
int ldb_dn_cmp(const char *dn1, const char *dn2)
{
	return ldb_caseless_cmp(dn1, dn2);
}

/*
  compare two attributes
  return 0 for match
*/
int ldb_attr_cmp(const char *dn1, const char *dn2)
{
	return ldb_caseless_cmp(dn1, dn2);
}
