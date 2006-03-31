/* 
   Unix SMB/CIFS implementation.
   Generic parameter parsing interface
   Copyright (C) Jelmer Vernooij					  2005
   
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

#ifndef _PARAM_H /* _PARAM_H */
#define _PARAM_H 

struct param_context {
	struct param_section *sections;
};

struct param {
	const char *name;
	char *value;
	const char **list_value;
	struct param *prev, *next;
};

struct param_section {
	const char *name;
	struct param_section *prev, *next;
	struct param *parameters;
};

struct param_context;
struct smbsrv_connection;

#define Auto (2)

#include "param/proto.h"

#endif /* _PARAM_H */
