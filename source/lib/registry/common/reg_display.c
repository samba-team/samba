/*
   Unix SMB/CIFS implementation.

   Copyright (C) Gerald Carter                     2001
   Copyright (C) Tim Potter                        2000
   Copyright (C) Jelmer Vernooij				   2004
 
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

void display_reg_value(REG_VAL *value)
{
	pstring text;

	switch(reg_val_type(value)) {
	case REG_DWORD:
		printf("%s: REG_DWORD: 0x%08x\n", reg_val_name(value), 
		       *((uint32 *) reg_val_data_blk(value)));
		break;
	case REG_SZ:
		rpcstr_pull(text, reg_val_data_blk(value), sizeof(text), reg_val_size(value),
			    STR_TERMINATE);
		printf("%s: REG_SZ: %s\n", reg_val_name(value), text);
		break;
	case REG_BINARY:
		printf("%s: REG_BINARY: unknown length value not displayed\n",
		       reg_val_name(value));
		break;
	case REG_MULTI_SZ: {
		uint16 *curstr = (uint16 *) reg_val_data_blk(value);
		uint8 *start = reg_val_data_blk(value);
		printf("%s: REG_MULTI_SZ:\n", reg_val_name(value));
		while ((*curstr != 0) && 
		       ((uint8 *) curstr < start + reg_val_size(value))) {
			rpcstr_pull(text, curstr, sizeof(text), -1, 
				    STR_TERMINATE);
			printf("  %s\n", text);
			curstr += strlen(text) + 1;
		}
	}
	break;
	default:
		printf("%s: unknown type %d\n", reg_val_name(value), reg_val_type(value));
	}
	
}
