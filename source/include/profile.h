/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   store smbd profiling information in shared memory
   Copyright (C) Andrew Tridgell 1999
   
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

/* this file defines the profile structure in the profile shared
   memory area */

struct profile_struct {
	unsigned smb_count; /* how many SMB packets we have processed */
	unsigned uid_changes; /* how many times we change our effective uid */
};


extern struct profile_struct *profile_p;
