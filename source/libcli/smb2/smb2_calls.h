/* 
   Unix SMB/CIFS implementation.

   SMB2 client calls 

   Copyright (C) Andrew Tridgell 2005
   
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


struct smb2_negprot {
	struct {
		uint32_t unknown1;    /* 0x00010024 */
		uint16_t unknown2;    /* 0x00 */
		uint8_t  unknown3[32]; /* all zero */
	} in;
	struct {
		uint32_t unknown1; /* 0x41 */
		uint32_t unknown2; /* 0x06 */
		uint8_t  sessid[16];
		uint32_t unknown3; /* 0x0d */
		uint16_t unknown4; /* 0x00 */
		uint32_t unknown5; /* 0x01 */
		uint32_t unknown6; /* 0x01 */
		uint16_t unknown7; /* 0x01 */
		NTTIME   current_time;
		NTTIME   boot_time;
		uint16_t unknown8; /* 0x80 */
		/* uint16_t secblob size here */
		uint32_t unknown9; /* 0x204d4c20 */
		DATA_BLOB secblob;
	} out;
};

struct smb2_session_setup {
	struct {
		uint32_t unknown1; /* 0x11 */
		uint32_t unknown2; /* 0xF */
		uint32_t unknown3; /* 0x00 */
		/* uint16_t secblob ofs/size here */
		DATA_BLOB secblob;
	} in;
	struct {
		uint32_t unknown1; /* 0x09 */
		/* uint16_t secblob ofs/size here */
		DATA_BLOB secblob;
		uint64_t uid; /* returned in header */
	} out;
};

struct smb2_tree_connect {
	struct {
		uint32_t unknown1; /* 0x09 */
		const char *path;
	} in;
	struct {
		uint32_t unknown1; /* 0x00020010 */
		uint32_t unknown2; /* 0x00 */
		uint32_t unknown3; /* 0x00 */
		uint32_t unknown4; /* 0x1f01ff */ /* capabilities?? */
		uint64_t tid;
	} out;
};
