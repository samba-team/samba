/* 
   Unix SMB/CIFS implementation.

   definitions for marshalling/unmarshalling security descriptors
   and related structures

   Copyright (C) Andrew Tridgell 2003
   
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


/* 
 use the same structure for dom_sid2 as dom_sid. A dom_sid2 is really
 just a dom sid, but with the sub_auths represented as a conformant
 array. As with all in-structure conformant arrays, the array length
 is placed before the start of the structure. That's what gives rise
 to the extra num_auths elemenent. We don't want the Samba code to
 have to bother with such esoteric NDR details, so its easier to just
 define it as a dom_sid and use pidl magic to make it all work. It
 just means you need to mark a sid as a "dom_sid2" in the IDL when you
 know it is of the conformant array variety
*/
#define dom_sid2 dom_sid

/* query security descriptor */
struct smb_query_secdesc {
	struct {
		uint16 fnum;
		uint32_t secinfo_flags;
	} in;
	struct {
		struct security_descriptor *sd;
	} out;
};

/* set security descriptor */
struct smb_set_secdesc {
	struct {
		uint16 fnum;
		uint32_t secinfo_flags;
		struct security_descriptor *sd;
	} in;
};
