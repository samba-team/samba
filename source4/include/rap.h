/* 
   Unix SMB/CIFS implementation.
   RAP operations
   Copyright (C) Volker Lendecke 2004
   
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

struct rap_shareenum_info_0 {
	char name[13];
};

struct rap_shareenum_info_1 {
	char name[13];
	char pad;
	uint16 type;
	char *comment;
};

union rap_shareenum_info {
	struct rap_shareenum_info_0 info0;
	struct rap_shareenum_info_1 info1;
};

struct rap_NetShareEnum {
	struct {
		uint16 level;
		uint16 bufsize;
	} in;

	struct {
		uint16 status;
		uint16 convert;
		uint16 count;
		uint16 available;
		union rap_shareenum_info *info;
	} out;
};

struct rap_server_info_0 {
	char name[16];
};

struct rap_server_info_1 {
        char     name[16];
        uint8_t  version_major;
        uint8_t  version_minor;
        uint32_t servertype;
        char    *comment;
};

union rap_server_info {
	struct rap_server_info_0 info0;
	struct rap_server_info_1 info1;
};

struct rap_NetServerEnum2 {
	struct {
		uint16 level;
		uint16 bufsize;
		uint32 servertype;
		const char *domain;
	} in;

	struct {
		uint16 status;
		uint16 convert;
		uint16 count;
		uint16 available;
		union rap_server_info *info;
	} out;
};
