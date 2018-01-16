/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIBSMB_UNEXPECTED_H__
#define __LIBSMB_UNEXPECTED_H__

#include "replace.h"
#include <tevent.h>
#include "libcli/util/ntstatus.h"
#include "nameserv.h"

struct nb_packet_server;
struct nb_packet_reader;

NTSTATUS nb_packet_server_create(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 int max_clients,
				 struct nb_packet_server **presult);
void nb_packet_dispatch(struct nb_packet_server *server,
			struct packet_struct *p);
struct tevent_req *nb_packet_reader_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 enum packet_type type,
					 int trn_id,
					 const char *mailslot_name);
NTSTATUS nb_packet_reader_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			       struct nb_packet_reader **preader);
struct tevent_req *nb_packet_read_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct nb_packet_reader *reader);
NTSTATUS nb_packet_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			     struct packet_struct **ppacket);

#endif
