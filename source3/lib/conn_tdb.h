/*
   Unix SMB/CIFS implementation.
   Low-level connections.tdb access functions
   Copyright (C) Volker Lendecke 2007

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

/* key and data in the connections database - used in smbstatus and smbd */
struct connections_key {
	struct server_id pid;
	int cnum;
	fstring name;
};

struct connections_data {
	struct server_id pid;
	int cnum;
	uid_t uid;
	gid_t gid;
	char servicename[FSTRING_LEN];
	char addr[FSTRING_LEN];
	char machine[FSTRING_LEN];
	time_t start;
};

/* The following definitions come from lib/conn_tdb.c  */

int connections_forall_read(int (*fn)(const struct connections_key *key,
				      const struct connections_data *data,
				      void *private_data),
			    void *private_data);
