/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell 1992-2004
   Copyright (C) Simo Sorce      2001-2002
   Copyright (C) Martin Pool     2003
   
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
#include "system/network.h"

/**
 List of Strings manipulation functions
**/

#define S_LIST_ABS 16 /* List Allocation Block Size */

char **str_list_make(const char *string, const char *sep)
{
	char **list, **rlist;
	const char *str;
	char *s;
	int num, lsize;
	pstring tok;
	
	if (!string || !*string)
		return NULL;
	s = strdup(string);
	if (!s) {
		DEBUG(0,("str_list_make: Unable to allocate memory"));
		return NULL;
	}
	if (!sep) sep = LIST_SEP;
	
	num = lsize = 0;
	list = NULL;
	
	str = s;
	while (next_token(&str, tok, sep, sizeof(tok))) {		
		if (num == lsize) {
			lsize += S_LIST_ABS;
			rlist = realloc_p(list, char *, lsize + 1);
			if (!rlist) {
				DEBUG(0,("str_list_make: Unable to allocate memory"));
				str_list_free(&list);
				SAFE_FREE(s);
				return NULL;
			} else
				list = rlist;
			memset (&list[num], 0, ((sizeof(char**)) * (S_LIST_ABS +1)));
		}
		
		list[num] = strdup(tok);
		if (!list[num]) {
			DEBUG(0,("str_list_make: Unable to allocate memory"));
			str_list_free(&list);
			SAFE_FREE(s);
			return NULL;
		}
	
		num++;	
	}
	
	SAFE_FREE(s);
	return list;
}

BOOL str_list_copy(char ***dest, const char **src)
{
	char **list, **rlist;
	int num, lsize;
	
	*dest = NULL;
	if (!src)
		return False;
	
	num = lsize = 0;
	list = NULL;
		
	while (src[num]) {
		if (num == lsize) {
			lsize += S_LIST_ABS;
			rlist = realloc_p(list, char *, lsize + 1);
			if (!rlist) {
				DEBUG(0,("str_list_copy: Unable to re-allocate memory"));
				str_list_free(&list);
				return False;
			} else
				list = rlist;
			memset (&list[num], 0, ((sizeof(char **)) * (S_LIST_ABS +1)));
		}
		
		list[num] = strdup(src[num]);
		if (!list[num]) {
			DEBUG(0,("str_list_copy: Unable to allocate memory"));
			str_list_free(&list);
			return False;
		}

		num++;
	}
	
	*dest = list;
	return True;	
}

/**
   Return true if all the elements of the list match exactly.
 **/
BOOL str_list_compare(char **list1, char **list2)
{
	int num;
	
	if (!list1 || !list2)
		return (list1 == list2); 
	
	for (num = 0; list1[num]; num++) {
		if (!list2[num])
			return False;
		if (!strcsequal(list1[num], list2[num]))
			return False;
	}
	if (list2[num])
		return False; /* if list2 has more elements than list1 fail */
	
	return True;
}

void str_list_free(char ***list)
{
	char **tlist;
	
	if (!list || !*list)
		return;
	tlist = *list;
	for(; *tlist; tlist++)
		SAFE_FREE(*tlist);
	SAFE_FREE(*list);
}



