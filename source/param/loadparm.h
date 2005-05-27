/* 
   Unix SMB/CIFS implementation.
   
   type definitions for loadparm

   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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

/* the following are used by loadparm for option lists */
typedef enum {
	P_BOOL,P_INTEGER,P_LIST,P_STRING,P_USTRING,P_ENUM,P_SEP
} parm_type;

typedef enum {
	P_LOCAL,P_GLOBAL,P_SEPARATOR,P_NONE
} parm_class;

struct enum_list {
	int value;
	const char *name;
};

struct parm_struct {
	const char *label;
	parm_type type;
	parm_class class;
	void *ptr;
	BOOL (*special)(const char *, char **);
	const struct enum_list *enum_list;
	uint_t flags;
	union {
		BOOL bvalue;
		int ivalue;
		char *svalue;
		char cvalue;
		const char **lvalue;
	} def;
};
