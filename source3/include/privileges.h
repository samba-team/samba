/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   
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

#ifndef PRIVILEGES_H
#define PRIVILEGES_H

typedef struct LUID
{
	uint32 low;
	uint32 high;
} LUID;

typedef struct LUID_ATTR
{
	LUID luid;
	uint32 attr;
} LUID_ATTR ;

typedef struct privilege_set
{
	uint32 count;
	uint32 control;
	LUID_ATTR *set;
} PRIVILEGE_SET;

#endif /* _RPC_LSA_H */
