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
	P_BOOL,P_INTEGER,P_BYTES,P_LIST,P_STRING,P_USTRING,P_ENUM,P_SEP
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
	unsigned int flags;
	union {
		int bvalue;
		int ivalue;
		char *svalue;
		char cvalue;
		const char **lvalue;
	} def;
};

#define FLAG_BASIC 	0x0001 /* fundamental options */
#define FLAG_SHARE 	0x0002 /* file sharing options */
#define FLAG_PRINT 	0x0004 /* printing options */
#define FLAG_GLOBAL 	0x0008 /* local options that should be globally settable in SWAT */
#define FLAG_WIZARD 	0x0010 /* Parameters that the wizard will operate on */
#define FLAG_ADVANCED 	0x0020 /* Parameters that the wizard will operate on */
#define FLAG_DEVELOPER 	0x0040 /* Parameters that the wizard will operate on */
#define FLAG_DEPRECATED 0x1000 /* options that should no longer be used */
#define FLAG_HIDE  	0x2000 /* options that should be hidden in SWAT */
#define FLAG_DEFAULT    0x4000 /* this option was a default */
#define FLAG_CMDLINE    0x8000 /* this option was set from the command line */

#ifndef PRINTERS_NAME
#define PRINTERS_NAME "printers"
#endif

#ifndef HOMES_NAME
#define HOMES_NAME "homes"
#endif

