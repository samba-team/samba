/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher	2006

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

struct libnet_BecomeDC_Options {
	uint32_t domain_behavior_version;
	uint32_t config_behavior_version;
	uint32_t schema_object_version;
	uint32_t w2k3_update_revision;
};

struct libnet_BecomeDC_Callbacks {
	void *private_data;
	NTSTATUS (*check_options)(void *private_data, const struct libnet_BecomeDC_Options *options);
	NTSTATUS (*prepare_db)(void *private_data, void *todo);
	NTSTATUS (*schema_chunk)(void *private_data, void *todo);
	NTSTATUS (*config_chunk)(void *private_data, void *todo);
	NTSTATUS (*domain_chunk)(void *private_data, void *todo);
};

struct libnet_BecomeDC {
	struct {
		const char *domain_dns_name;
		const char *domain_netbios_name;
		const struct dom_sid *domain_sid;
		const char *source_dsa_address;
		const char *dest_dsa_netbios_name;

		struct libnet_BecomeDC_Callbacks callbacks;
	} in;

	struct {
		const char *error_string;
	} out;
};
