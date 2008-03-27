/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Jean François Micouleau 2002
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _RPC_NETLOGON_H /* _RPC_NETLOGON_H */
#define _RPC_NETLOGON_H 

/* LOCKOUT_STRING */
typedef struct account_lockout_string {
	uint32 array_size;
	uint32 offset;
	uint32 length;
/*	uint16 *bindata;	*/
	uint64 lockout_duration;
	uint64 reset_count;
	uint32 bad_attempt_lockout;
	uint32 dummy;
} LOCKOUT_STRING;

/* HDR_LOCKOUT_STRING */
typedef struct hdr_account_lockout_string {
	uint16 size;
	uint16 length;
	uint32 buffer;
} HDR_LOCKOUT_STRING;

struct DS_DOMAIN_CONTROLLER_INFO {
	const char *domain_controller_name;
	const char *domain_controller_address;
	int32 domain_controller_address_type;
	struct GUID *domain_guid;
	const char *domain_name;
	const char *dns_forest_name;
	uint32 flags;
	const char *dc_site_name;
	const char *client_site_name;
};

#endif /* _RPC_NETLOGON_H */
