/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2001.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

typedef struct _GROUP_MAP {
	gid_t gid;
	DOM_SID sid;
	enum SID_NAME_USE sid_name_use;
	fstring nt_name;
	fstring comment;
	uint32 privilege;
} GROUP_MAP;

typedef struct _PRIVS {
	uint32 se_priv;
	const char *priv;
	const char *description;
} PRIVS;

#define SE_PRIV_NONE		0x0000
#define SE_PRIV_ADD_USERS	0x0001
#define SE_PRIV_ADD_MACHINES	0x0002
#define SE_PRIV_PRINT_OPERATOR	0x0004
#define SE_PRIV_ALL		0xffff

#define PRIV_ALL_INDEX		4


#define ENUM_ONLY_MAPPED True
#define ENUM_ALL_MAPPED False
