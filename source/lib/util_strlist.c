/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell 2005
   
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

/*
  build a null terminated list of strings from a input string and a
  separator list. The sepatator list must contain characters less than
  or equal to 0x2f for this to work correctly on multi-byte strings
*/
char **str_list_make(TALLOC_CTX *mem_ctx, const char *string, const char *sep)
{
	int num_elements = 0;
	char **ret = NULL;

	if (sep == NULL) {
		sep = LIST_SEP;
	}

	ret = talloc_realloc(mem_ctx, NULL, char *, 1);
	if (ret == NULL) {
		return NULL;
	}

	while (string && *string) {
		size_t len = strcspn(string, sep);
		char **ret2;
		
		if (len == 0) {
			string += strspn(string, sep);
			continue;
		}

		ret2 = talloc_realloc(mem_ctx, ret, char *, num_elements+2);
		if (ret2 == NULL) {
			talloc_free(ret);
			return NULL;
		}
		ret = ret2;

		ret[num_elements] = talloc_strndup(ret, string, len);
		if (ret[num_elements] == NULL) {
			talloc_free(ret);
			return NULL;
		}

		num_elements++;
		string += len;
	}

	ret[num_elements] = NULL;

	return ret;
}

/*
  return the number of elements in a string list
*/
size_t str_list_length(const char **list)
{
	size_t ret;
	for (ret=0;list && list[ret];ret++) /* noop */ ;
	return ret;
}


/*
  copy a string list
*/
char **str_list_copy(TALLOC_CTX *mem_ctx, const char **list)
{
	int i;
	char **ret = talloc_array(mem_ctx, char *, str_list_length(list)+1);
	if (ret == NULL) return NULL;

	for (i=0;list && list[i];i++) {
		ret[i] = talloc_strdup(ret, list[i]);
		if (ret[i] == NULL) {
			talloc_free(ret);
			return NULL;
		}
	}
	ret[i] = NULL;
	return ret;
}

/*
   Return true if all the elements of the list match exactly.
 */
BOOL str_list_equal(const char **list1, const char **list2)
{
	int i;
	
	if (list1 == NULL || list2 == NULL) {
		return (list1 == list2); 
	}
	
	for (i=0;list1[i] && list2[i];i++) {
		if (strcmp(list1[i], list2[i]) != 0) {
			return False;
		}
	}
	if (list1[i] || list2[i]) {
		return False;
	}
	return True;
}
