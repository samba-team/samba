/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   
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

/* struct and enum for doing a remote domain join */
enum libnet_JoinDomain_level {
	LIBNET_JOIN_DOMAIN_GENERIC,
	LIBNET_JOIN_DOMAIN_SAMR,
};

union libnet_JoinDomain {
	struct {
		enum libnet_JoinDomain_level level;

		struct _libnet_JoinDomain_in {
			const char *domain_name;
			const char *account_name;
			uint32      acct_type;
		} in;

		struct _libnet_JoinDomain_out {
			const char *error_string;
			const char *join_password;
		} out;
	} generic;

	struct {
		enum libnet_JoinDomain_level level;
		struct _libnet_JoinDomain_in in;
		struct _libnet_JoinDomain_out out;
	} samr;

};

