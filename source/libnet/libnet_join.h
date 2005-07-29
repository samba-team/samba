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

#include "librpc/gen_ndr/ndr_netlogon.h"

struct libnet_JoinDomain {
	struct {
		const char *domain_name;
		const char *account_name;
		uint32_t  acct_type;
	} in;

	struct {
		const char *error_string;
		const char *join_password;
		struct dom_sid *domain_sid;
		const char *domain_name;
		const char *realm;
	} out;
};

struct libnet_Join {
	struct {
		const char *domain_name;
		enum netr_SchannelType secure_channel_type;
	} in;
	
	struct {
		const char *error_string;
	} out;
};

