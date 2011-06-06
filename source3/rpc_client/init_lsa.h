#ifndef __RPC_CLIENT_INIT_LSA_H__
#define __RPC_CLIENT_INIT_LSA_H__

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

struct lsa_String;
struct lsa_StringLarge;
struct lsa_AsciiString;
struct lsa_AsciiStringLarge;

/* The following definitions come from rpc_client/init_lsa.c  */

void init_lsa_String(struct lsa_String *name, const char *s);
void init_lsa_StringLarge(struct lsa_StringLarge *name, const char *s);
void init_lsa_AsciiString(struct lsa_AsciiString *name, const char *s);
void init_lsa_AsciiStringLarge(struct lsa_AsciiStringLarge *name, const char *s);
#endif
