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

#ifndef SIDS_H
#define SIDS_H 

extern DOM_SID global_sam_sid;
extern fstring global_sam_name;

extern DOM_SID global_member_sid;

extern DOM_SID global_sid_S_1_5_20; /* local well-known domain */
extern DOM_SID global_sid_S_1_1;    /* everyone */
extern DOM_SID global_sid_S_1_3;    /* Creator Owner */
extern DOM_SID global_sid_S_1_5;    /* NT Authority */

#endif /* SIDS_H */
