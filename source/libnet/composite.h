/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Rafal Szczesniak 2005
   
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

/*
 * Monitor structure and message types definitions. Composite function monitoring
 * allows client application to be notified on function progress. This enables
 * eg. gui client to display progress bars, status messages, etc.
 */


#define  rpc_create_user        (0x00000001)
#define  rpc_open_user          (0x00000002)
#define  rpc_query_user         (0x00000003)
#define  rpc_close_user         (0x00000004)
#define  rpc_lookup_name        (0x00000005)
#define  rpc_delete_user        (0x00000006)
#define  rpc_set_user           (0x00000007)
#define  rpc_close              (0x00000008)
#define  rpc_connect            (0x00000009)
#define  rpc_lookup_domain      (0x00000010)
#define  rpc_open_domain        (0x00000011)
#define  rpc_open_policy        (0x00000012)
#define  rpc_query_policy       (0x00000013)

#define  net_lookup_dc          (0x00000100)
#define  net_rpc_connect        (0x00000200)


struct monitor_msg {
	uint32_t   type;
	void       *data;
	size_t     data_size;
};
