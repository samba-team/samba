/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1999
   
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


/****************************************************************************
convert a security permissions into a string
****************************************************************************/
char *get_reg_val_type_str(uint32 type)
{
	static fstring typestr;

	switch (type)
	{
		case 0x01:
		{
			fstrcpy(typestr, "string");
			return typestr;
		}

		case 0x03:
		{
			fstrcpy(typestr, "bytes");
			return typestr;
		}

		case 0x04:
		{
			fstrcpy(typestr, "uint32");
			return typestr;
		}

		case 0x07:
		{
			fstrcpy(typestr, "multi");
			return typestr;
		}
		default:
		{
			break;
		}
	}
	slprintf(typestr, sizeof(typestr)-1, "[%d]", type);
	return typestr;
}


static void print_reg_value(FILE *out_hnd, const char *val_name, 
				uint32 val_type, const BUFFER2 *value)
{
	fstring type;
	fstring valstr;

	fstrcpy(type, get_reg_val_type_str(val_type));

	switch (val_type)
	{
		case 0x01: /* unistr */
		{
			unibuf_to_ascii(valstr, value->buffer, 
					MIN(value->buf_len, sizeof(valstr)-1));
			report(out_hnd, "\t%s:\t%s:\t%s\n", val_name, type, valstr);
			break;
		}

		default: /* unknown */
		case 0x03: /* bytes */
		{
			if (value->buf_len <= 8)
			{
				report(out_hnd, "\t%s:\t%s:\t", val_name, type);
				out_data(out_hnd, (const char*)value->buffer, 
				         value->buf_len, 8, "");
			}
			else
			{
				report(out_hnd, "\t%s:\t%s:\n", val_name, type);
				out_data(out_hnd, (const char*)value->buffer, 
				         value->buf_len, 16, "");
			}
			break;
		}

		case 0x04: /* uint32 */
		{
			report(out_hnd, "\t%s:\t%s:\t0x%08x\n", val_name, type, buffer2_to_uint32(value));
			break;
		}

		case 0x07: /* multiunistr */
		{
			buffer2_to_multistr(valstr, value, sizeof(valstr)-1);
			report(out_hnd, "\t%s:\t%s:\t%s\n", val_name, type, valstr);
			break;
		}
	}
}

/****************************************************************************
 display structure
 ****************************************************************************/
void display_reg_value_info(FILE *out_hnd, enum action_type action, 
				const char *val_name, 
				uint32 val_type, const BUFFER2 *value)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			print_reg_value(out_hnd, val_name, val_type, value);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
 display structure
 ****************************************************************************/
void display_reg_key_info(FILE *out_hnd, enum action_type action, 
				const char *key_name, time_t key_mod_time)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			report(out_hnd, "\t%s\t(%s)\n", 
			        key_name, http_timestring(key_mod_time));
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

