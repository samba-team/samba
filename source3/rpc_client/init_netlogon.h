#ifndef __RPC_CLIENT_INIT_NETLOGON_H__
#define __RPC_CLIENT_INIT_NETLOGON_H__

/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

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

/* The following definitions come from rpc_client/init_netlogon.c  */

void init_netr_CryptPassword(const char *pwd,
			     unsigned char session_key[16],
			     struct netr_CryptPassword *pwd_buf);
#endif
