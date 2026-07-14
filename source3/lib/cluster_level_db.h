/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2026

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

#ifndef CLUSTER_LEVEL_DB_H
#define CLUSTER_LEVEL_DB_H

struct ctdbd_connection;

NTSTATUS cluster_level_db_check(struct ctdbd_connection *ctdb_conn);

#endif /* CLUSTER_LEVEL_DB_H */
