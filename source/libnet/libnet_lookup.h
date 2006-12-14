/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Rafal Szczesniak 2005
   
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


struct libnet_Lookup {
	struct {
		const char *hostname;
		int type;
		const char **methods;
	} in;
	struct {
		const char **address;
	} out;
};


struct libnet_LookupDCs {
	struct {
		const char *domain_name;
		int name_type;
	} in;
	struct {
		int num_dcs;
		struct nbt_dc_name *dcs;
	} out;
};


struct libnet_LookupName {
	struct {
		const char *name;
		const char *domain_name;
	} in;
	struct {
		struct dom_sid *sid;
		int rid;
		enum lsa_SidType sid_type;
		const char *sidstr;
		const char *error_string;
	} out;
};
