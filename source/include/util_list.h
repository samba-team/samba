/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell                   1992-1999
   Copyright (C) Gerald Carter <jerry@samba.org>   2000
   
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

/******************************************************************
 Implementation of a generic list.  See lib/util_list.c for
 details on using this.
 *****************************************************************/

#include "smb.h"

#ifndef _GENERIC_LIST_H
#define _GENERIC_LIST_H

struct _list_node;

/* 
 * node container in list 
 */
struct _list_node {
	
	void			*data;	/* generic container pointer */
	uint8			type;	/* needed for identifiers 
					   in a hetergenous list */
	struct _list_node	*next;  /* next in the list */

};

/* 
 * list data structure 
 */
typedef struct _generic_list {

	struct _list_node	*head, *tail;
	uint32			length;
	BOOL			initialized;

} GENERIC_LIST;	
	

#endif /* _GENERIC_LIST_H */
