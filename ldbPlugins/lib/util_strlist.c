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
			rlist = (char **)Realloc(list, ((sizeof(char **)) * (lsize +1)));
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
			rlist = (char **)Realloc(list, ((sizeof(char **)) * (lsize +1)));
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

BOOL str_list_substitute(char **list, const char *pattern, const char *insert)
{
	char *p, *s, *t;
	ssize_t ls, lp, li, ld, i, d;

	if (!list)
		return False;
	if (!pattern)
		return False;
	if (!insert)
		return False;

	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);
	ld = li -lp;
			
	while (*list) {
		s = *list;
		ls = (ssize_t)strlen(s);

		while ((p = strstr(s, pattern))) {
			t = *list;
			d = p -t;
			if (ld) {
				t = (char *) malloc(ls +ld +1);
				if (!t) {
					DEBUG(0,("str_list_substitute: Unable to allocate memory"));
					return False;
				}
				memcpy(t, *list, d);
				memcpy(t +d +li, p +lp, ls -d -lp +1);
				SAFE_FREE(*list);
				*list = t;
				ls += ld;
				s = t +d +li;
			}
			
			for (i = 0; i < li; i++) {
				switch (insert[i]) {
					case '`':
					case '"':
					case '\'':
					case ';':
					case '$':
					case '%':
					case '\r':
					case '\n':
						t[d +i] = '_';
						break;
					default:
						t[d +i] = insert[i];
				}
			}	
		}
		
		list++;
	}
	
	return True;
}


#define IPSTR_LIST_SEP	","

/**
 * Add ip string representation to ipstr list. Used also
 * as part of @function ipstr_list_make
 *
 * @param ipstr_list pointer to string containing ip list;
 *        MUST BE already allocated and IS reallocated if necessary
 * @param ipstr_size pointer to current size of ipstr_list (might be changed
 *        as a result of reallocation)
 * @param ip IP address which is to be added to list
 * @return pointer to string appended with new ip and possibly
 *         reallocated to new length
 **/

char* ipstr_list_add(char** ipstr_list, const struct ipv4_addr *ip)
{
	char* new_ipstr = NULL;
	
	/* arguments checking */
	if (!ipstr_list || !ip) return NULL;

	/* attempt to convert ip to a string and append colon separator to it */
	if (*ipstr_list) {
		asprintf(&new_ipstr, "%s%s%s", *ipstr_list, IPSTR_LIST_SEP,sys_inet_ntoa(*ip));
		SAFE_FREE(*ipstr_list);
	} else {
		asprintf(&new_ipstr, "%s", sys_inet_ntoa(*ip));
	}
	*ipstr_list = new_ipstr;
	return *ipstr_list;
}

/**
 * Allocate and initialise an ipstr list using ip adresses
 * passed as arguments.
 *
 * @param ipstr_list pointer to string meant to be allocated and set
 * @param ip_list array of ip addresses to place in the list
 * @param ip_count number of addresses stored in ip_list
 * @return pointer to allocated ip string
 **/
 
char* ipstr_list_make(char** ipstr_list, const struct ipv4_addr* ip_list, int ip_count)
{
	int i;
	
	/* arguments checking */
	if (!ip_list && !ipstr_list) return 0;

	*ipstr_list = NULL;
	
	/* process ip addresses given as arguments */
	for (i = 0; i < ip_count; i++)
		*ipstr_list = ipstr_list_add(ipstr_list, &ip_list[i]);
	
	return (*ipstr_list);
}


/**
 * Parse given ip string list into array of ip addresses
 * (as in_addr structures)
 *
 * @param ipstr ip string list to be parsed 
 * @param ip_list pointer to array of ip addresses which is
 *        allocated by this function and must be freed by caller
 * @return number of succesfully parsed addresses
 **/
 
int ipstr_list_parse(const char* ipstr_list, struct ipv4_addr** ip_list)
{
	fstring token_str;
	int count;

	if (!ipstr_list || !ip_list) return 0;
	
	for (*ip_list = NULL, count = 0;
	     next_token(&ipstr_list, token_str, IPSTR_LIST_SEP, FSTRING_LEN);
	     count++) {
	     
		struct ipv4_addr addr;

		/* convert single token to ip address */
		if ( (addr.addr = sys_inet_addr(token_str)) == INADDR_NONE )
			break;
		
		/* prepare place for another in_addr structure */
		*ip_list = Realloc(*ip_list, (count + 1) * sizeof(struct ipv4_addr));
		if (!*ip_list) return -1;
		
		(*ip_list)[count] = addr;
	}
	
	return count;
}


/**
 * Safely free ip string list
 *
 * @param ipstr_list ip string list to be freed
 **/

void ipstr_list_free(char* ipstr_list)
{
	SAFE_FREE(ipstr_list);
}
