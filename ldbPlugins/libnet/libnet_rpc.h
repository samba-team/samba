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

/* struct and enum for finding a domain controller */
enum libnet_find_pdc_level {
	LIBNET_FIND_PDC_GENERIC
};

union libnet_find_pdc {
	/* find to a domains PDC */
	struct {
		enum libnet_find_pdc_level level;

		struct {
			const char *domain_name;
		} in;

		struct	{
			const char *pdc_name;
		} out;
	} generic;
};

/* struct and enum for connecting to a dcerpc inferface */
enum libnet_rpc_connect_level {
	LIBNET_RPC_CONNECT_STANDARD,
	LIBNET_RPC_CONNECT_PDC
};

union libnet_rpc_connect {
	/* connect to a standart server */
	struct {
		enum libnet_rpc_connect_level level;

		struct {
			const char *server_name;
			const char *dcerpc_iface_name;
			const char *dcerpc_iface_uuid;
			uint32 dcerpc_iface_version;
		} in;

		struct _libnet_rpc_connect_out {
			struct dcerpc_pipe *dcerpc_pipe;
			const char *error_string;
		} out;
	} standard;

	/* connect to a domains PDC */
	struct {
		enum libnet_rpc_connect_level level;

		struct {
			const char *domain_name;
			const char *dcerpc_iface_name;
			const char *dcerpc_iface_uuid;
			uint32 dcerpc_iface_version;
		} in;

		struct _libnet_rpc_connect_out out;
	} pdc;
};
