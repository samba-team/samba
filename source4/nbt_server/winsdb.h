/* 
   Unix SMB/CIFS implementation.

   WINS server structures

   Copyright (C) Andrew Tridgell	2005
   
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

enum wins_record_state {
	WINS_REC_RELEASED =0,
	WINS_REC_ACTIVE   =1,
	WINS_REC_EXPIRED  =2
};

/*
  each record in the database contains the following information
*/
struct winsdb_record {
	struct nbt_name *name;
	uint16_t nb_flags;
	enum wins_record_state state;
	time_t expire_time;
	const char *registered_by;
	const char **addresses;
};

struct wins_server {
	/* wins server database handle */
	struct ldb_wrap *wins_db;

	uint32_t min_ttl;
	uint32_t max_ttl;
};
