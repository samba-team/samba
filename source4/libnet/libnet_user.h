/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Rafal Szczesniak <mimir@samba.org> 2005
   
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


enum libnet_CreateUser_level {
	LIBNET_CREATE_USER_GENERIC,
	LIBNET_CREATE_USER_SAMR,
};


union libnet_CreateUser {
	struct {
		enum libnet_CreateUser_level level;

		struct _libnet_CreateUser_in {
			const char *user_name;
			const char *domain_name;
		} in;
		
		struct _libnet_CreateUser_out {
			const char *error_string;
		} out;
	} generic;

	struct {
		enum libnet_CreateUser_level level;
		struct _libnet_CreateUser_in in;
		struct _libnet_CreateUser_out out;
	} samr;
};
