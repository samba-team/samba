/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell              1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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

void free_void_array(uint32 num_entries, void **entries,
		void(free_item)(void*))
{
	uint32 i;
	if (entries != NULL)
	{
		if (free_item != NULL)
		{
			for (i = 0; i < num_entries; i++)
			{
				if (entries[i] != NULL)
				{
					free_item(entries[i]);
				}
			}
		}
		free(entries);
	}
}

void* add_copy_to_array(uint32 *len, void ***array, const void *item,
	void*(item_dup)(const void*), BOOL alloc_anyway)
{
	void* copy = NULL;
	if (len == NULL || array == NULL)
	{
		return NULL;
	}

	if (item != NULL || alloc_anyway)
	{
		copy = item_dup(item);
		return add_item_to_array(len, array, copy);
	}
	return copy;
}

void* add_item_to_array(uint32 *len, void ***array, void *item)
{
	if (len == NULL || array == NULL)
	{
		return NULL;
	}

	(*array) = (void**)Realloc((*array), ((*len)+1)*sizeof((*array)[0]));

	if ((*array) != NULL)
	{
		(*array)[(*len)] = item;
		(*len)++;
		return item;
	}
	return NULL;
}

static void use_info_free(struct use_info *item)
{
	if (item != NULL)
	{
		if (item->srv_name != NULL)
		{
			free(item->srv_name);
		}
		if (item->user_name != NULL)
		{
			free(item->user_name);
		}
		if (item->domain != NULL)
		{
			free(item->domain);
		}
		free(item);
	}
}

static struct use_info *use_info_dup(const struct use_info *from)
{
	if (from != NULL)
	{
		struct use_info *copy = (struct use_info *)
		                        malloc(sizeof(struct use_info));
		if (copy != NULL)
		{
			ZERO_STRUCTP(copy);
			copy->connected = from->connected;
			copy->key = from->key;
			if (from->srv_name != NULL)
			{
				copy->srv_name  = strdup(from->srv_name );
			}
			if (from->user_name != NULL)
			{
				copy->user_name = strdup(from->user_name);
			}
			if (from->domain != NULL)
			{
				copy->domain    = strdup(from->domain   );
			}
		}
		return copy;
	}
	return NULL;
}

void free_use_info_array(uint32 num_entries, struct use_info **entries)
{
	void(*fn)(void*) = (void(*)(void*))&use_info_free;
	free_void_array(num_entries, (void**)entries, *fn);
}

struct use_info* add_use_info_to_array(uint32 *len, struct use_info ***array,
				const struct use_info *name)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&use_info_dup;
	return (struct use_info*)add_copy_to_array(len,
	                     (void***)array, (const void*)name, *fn, False);
				
}

void free_char_array(uint32 num_entries, char **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free;
	free_void_array(num_entries, (void**)entries, *fn);
}

static char *Strdup(const char *name)
{
	if (name == NULL)
	{
		return NULL;
	}
	return strdup(name);
}

char* add_chars_to_array(uint32 *len, char ***array, const char *name)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&Strdup;
	return (char*)add_copy_to_array(len,
	                     (void***)array, (const void*)name, *fn, True);
				
}

static uint32 *uint32_dup(const uint32* from)
{
	if (from != NULL)
	{
		uint32 *copy = (uint32 *)malloc(sizeof(uint32));
		if (copy != NULL)
		{
			memcpy(copy, from, sizeof(*copy));
		}
		return copy;
	}
	return NULL;
}

void free_uint32_array(uint32 num_entries, uint32 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free;
	free_void_array(num_entries, (void**)entries, *fn);
}

#if 0

/* This function is completely broken. */

uint32* add_uint32s_to_array(uint32 *len, uint32 **array, const uint32 *name)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&uint32_dup;
	return (uint32*)add_copy_to_array(len,
	                     (void***)array, (const void*)name, *fn, False);
				
}

#endif

void free_unistr_array(uint32 num_entries, UNISTR2 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&unistr2_free;
	free_void_array(num_entries, (void**)entries, *fn);
}

UNISTR2* add_unistr_to_array(uint32 *len, UNISTR2 ***array, UNISTR2 *name)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&unistr2_dup;
	return (UNISTR2*)add_copy_to_array(len,
	                   (void***)array, (const void*)name, *fn, False);
}

void free_sid_array(uint32 num_entries, DOM_SID **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free;
	free_void_array(num_entries, (void**)entries, *fn);
}

DOM_SID* add_sid_to_array(uint32 *len, DOM_SID ***array, const DOM_SID *sid)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&sid_dup;
	return (DOM_SID*)add_copy_to_array(len,
	                  (void***)array, (const void*)sid, *fn, False);
}

