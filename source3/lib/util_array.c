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
		for (i = 0; i < num_entries; i++)
		{
			if (entries[i] != NULL)
			{
				free_item(entries[i]);
			}
		}
		free(entries);
	}
}

void* add_copy_to_array(uint32 *len, void ***array, const void *item,
	void*(item_dup)(const void*), BOOL alloc_anyway)
{
	if (len == NULL || array == NULL)
	{
		return NULL;
	}

	if (item != NULL || alloc_anyway)
	{
		void* copy = NULL;
		if (item != NULL || alloc_anyway)
		{
			copy = item_dup(item);
		}
		add_item_to_array(len, array, copy);
	}
	return NULL;
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

void free_use_array(uint32 num_entries, struct use_info **entries)
{
	void(*fn)(void*) = (void(*)(void*))&use_info_free;
	free_void_array(num_entries, (void**)entries, *fn);
}

struct use_info* add_use_to_array(uint32 *len, struct use_info ***array,
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

char* add_chars_to_array(uint32 *len, char ***array, const char *name)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&strdup;
	return (char*)add_copy_to_array(len,
	                     (void***)array, (const void*)name, *fn, False);
				
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

uint32* add_uint32s_to_array(uint32 *len, uint32 ***array, const uint32 *name)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&uint32_dup;
	return (uint32*)add_copy_to_array(len,
	                     (void***)array, (const void*)name, *fn, False);
				
}

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

void free_devmode(DEVICEMODE *devmode)
{
	if (devmode!=NULL)
	{
		if (devmode->private!=NULL)
			free(devmode->private);
		free(devmode);
	}
}

void free_printer_info_2(PRINTER_INFO_2 *printer)
{
	if (printer!=NULL)
	{
		free_devmode(printer->devmode);
		free(printer);
	}
}

static PRINTER_INFO_2 *prt2_dup(const PRINTER_INFO_2* from)
{
	PRINTER_INFO_2 *copy = (PRINTER_INFO_2 *)malloc(sizeof(PRINTER_INFO_2));
	if (copy != NULL)
	{
		if (from != NULL)
		{
			memcpy(copy, from, sizeof(*copy));
		}
		else
		{
			ZERO_STRUCTP(copy);
		}
	}
	return copy;
}

void free_print2_array(uint32 num_entries, PRINTER_INFO_2 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free_printer_info_2;
	free_void_array(num_entries, (void**)entries, *fn);
}

PRINTER_INFO_2 *add_print2_to_array(uint32 *len, PRINTER_INFO_2 ***array,
				const PRINTER_INFO_2 *prt)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&prt2_dup;
	return (PRINTER_INFO_2*)add_copy_to_array(len,
	           (void***)array, (const void*)prt, *fn, True);
}

static PRINTER_INFO_1 *prt1_dup(const PRINTER_INFO_1* from)
{
	PRINTER_INFO_1 *copy = (PRINTER_INFO_1 *)malloc(sizeof(PRINTER_INFO_1));
	if (copy != NULL)
	{
		if (from != NULL)
		{
			memcpy(copy, from, sizeof(*copy));
		}
		else
		{
			ZERO_STRUCTP(copy);
		}
	}
	return copy;
}

void free_print1_array(uint32 num_entries, PRINTER_INFO_1 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free;
	free_void_array(num_entries, (void**)entries, *fn);
}

PRINTER_INFO_1 *add_print1_to_array(uint32 *len, PRINTER_INFO_1 ***array,
				const PRINTER_INFO_1 *prt)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&prt1_dup;
	return (PRINTER_INFO_1*)add_copy_to_array(len,
	                   (void***)array, (const void*)prt, *fn, True);
}

static JOB_INFO_1 *job1_dup(const JOB_INFO_1* from)
{
	JOB_INFO_1 *copy = (JOB_INFO_1 *)malloc(sizeof(JOB_INFO_1));
	if (copy != NULL)
	{
		if (from != NULL)
		{
			memcpy(copy, from, sizeof(*copy));
		}
		else
		{
			ZERO_STRUCTP(copy);
		}
	}
	return copy;
}

void free_job1_array(uint32 num_entries, JOB_INFO_1 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free;
	free_void_array(num_entries, (void**)entries, *fn);
}

JOB_INFO_1 *add_job1_to_array(uint32 *len, JOB_INFO_1 ***array,
				const JOB_INFO_1 *job)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&job1_dup;
	return (JOB_INFO_1*)add_copy_to_array(len,
	                   (void***)array, (const void*)job, *fn, True);
}

static JOB_INFO_2 *job2_dup(const JOB_INFO_2* from)
{
	JOB_INFO_2 *copy = (JOB_INFO_2 *)malloc(sizeof(JOB_INFO_2));
	if (copy != NULL)
	{
		if (from != NULL)
		{
			memcpy(copy, from, sizeof(*copy));
		}
		else
		{
			ZERO_STRUCTP(copy);
		}
	}
	return copy;
}

void free_job2_array(uint32 num_entries, JOB_INFO_2 **entries)
{
	void(*fn)(void*) = (void(*)(void*))&free;
	free_void_array(num_entries, (void**)entries, *fn);
}

JOB_INFO_2 *add_job2_to_array(uint32 *len, JOB_INFO_2 ***array,
				const JOB_INFO_2 *job)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&job2_dup;
	return (JOB_INFO_2*)add_copy_to_array(len,
	                   (void***)array, (const void*)job, *fn, True);
}

