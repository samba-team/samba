/* 
   Unix SMB/Netbios implementation.

   Copyright (C) Andrew Tridgell              1992-2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
   Copyright (C) Jean Francois Micouleau      1998-2000.
   Copyright (C) Gerald Carter                2001-2005.
   
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

#ifndef _RPC_BUFFER_H		/* _RPC_SPOOLSS_H */
#define _RPC_BUFFER_H

typedef struct {
#if 0
	uint32 ptr;
#endif
	uint32 size;
	prs_struct prs;
	uint32 struct_start;
	uint32 string_at_end;
} RPC_BUFFER;


#endif 	/* _RPC_BUFFER_H */
