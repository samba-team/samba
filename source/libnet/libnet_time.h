/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   
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

/* struct and enum for getting the time of a remote system */
enum libnet_RemoteTOD_level {
	LIBNET_REMOTE_TOD_GENERIC,
	LIBNET_REMOTE_TOD_SRVSVC
};

union libnet_RemoteTOD {
	struct {
		enum libnet_RemoteTOD_level level;

		struct _libnet_RemoteTOD_in {
			const char *server_name;
		} in;

		struct _libnet_RemoteTOD_out {
			time_t time;
			int time_zone;
			const char *error_string;
		} out;
	} generic;

	struct {
		enum libnet_RemoteTOD_level level;
		struct _libnet_RemoteTOD_in in;
		struct _libnet_RemoteTOD_out out;
	} srvsvc;
};
