/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Elrond                            2000
   
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

#ifndef _SIDS_H
#define _SIDS_H 

extern DOM_SID global_sam_sid;
extern fstring global_sam_name;

extern DOM_SID global_member_sid;

extern DOM_SID global_sid_S_1_5_32; /* local well-known domain */
extern DOM_SID global_sid_S_1_1;    /* Global Domain */
extern DOM_SID global_sid_NULL;

extern const DOM_SID *global_sid_everyone;
extern const DOM_SID *global_sid_system;   /* SYSTEM */
extern const DOM_SID *global_sid_builtin;

#endif /* _SIDS_H */
