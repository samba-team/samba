/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon - sid related functions

   Copyright (C) Tim Potter 2000
   
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

#include "winbindd.h"

/* Convert a string to a sid */

enum winbindd_result winbindd_string2sid(struct winbindd_cli_state *state)
{
	return WINBINDD_ERROR;
}

/* Convert a sid to a string */

enum winbindd_result winbindd_sid2string(struct winbindd_cli_state *state)
{
	return WINBINDD_ERROR;
}
