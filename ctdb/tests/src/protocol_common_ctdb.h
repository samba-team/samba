/*
   protocol tests - ctdb protocol

   Copyright (C) Amitay Isaacs  2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_PROTOCOL_COMMON_CTDB_H__
#define __CTDB_PROTOCOL_COMMON_CTDB_H__

#include "replace.h"
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

#include "protocol/protocol.h"

void fill_ctdb_req_header(struct ctdb_req_header *h);
void verify_ctdb_req_header(struct ctdb_req_header *h,
			    struct ctdb_req_header *h2);

void fill_ctdb_req_call(TALLOC_CTX *mem_ctx, struct ctdb_req_call *c);
void verify_ctdb_req_call(struct ctdb_req_call *c, struct ctdb_req_call *c2);

void fill_ctdb_reply_call(TALLOC_CTX *mem_ctx, struct ctdb_reply_call *c);
void verify_ctdb_reply_call(struct ctdb_reply_call *c,
			    struct ctdb_reply_call *c2);

void fill_ctdb_reply_error(TALLOC_CTX *mem_ctx, struct ctdb_reply_error *c);
void verify_ctdb_reply_error(struct ctdb_reply_error *c,
			     struct ctdb_reply_error *c2);

void fill_ctdb_req_dmaster(TALLOC_CTX *mem_ctx, struct ctdb_req_dmaster *c);
void verify_ctdb_req_dmaster(struct ctdb_req_dmaster *c,
			     struct ctdb_req_dmaster *c2);

void fill_ctdb_reply_dmaster(TALLOC_CTX *mem_ctx,
			     struct ctdb_reply_dmaster *c);
void verify_ctdb_reply_dmaster(struct ctdb_reply_dmaster *c,
			       struct ctdb_reply_dmaster *c2);

void fill_ctdb_req_control_data(TALLOC_CTX *mem_ctx,
				struct ctdb_req_control_data *cd,
				uint32_t opcode);
void verify_ctdb_req_control_data(struct ctdb_req_control_data *cd,
				  struct ctdb_req_control_data *cd2);

void fill_ctdb_req_control(TALLOC_CTX *mem_ctx, struct ctdb_req_control *c,
			   uint32_t opcode);
void verify_ctdb_req_control(struct ctdb_req_control *c,
			     struct ctdb_req_control *c2);

void fill_ctdb_reply_control_data(TALLOC_CTX *mem_ctx,
				  struct ctdb_reply_control_data *cd,
				  uint32_t opcode);
void verify_ctdb_reply_control_data(struct ctdb_reply_control_data *cd,
				    struct ctdb_reply_control_data *cd2);

void fill_ctdb_reply_control(TALLOC_CTX *mem_ctx,
			     struct ctdb_reply_control *c, uint32_t opcode);
void verify_ctdb_reply_control(struct ctdb_reply_control *c,
			       struct ctdb_reply_control *c2);

void fill_ctdb_message_data(TALLOC_CTX *mem_ctx, union ctdb_message_data *md,
			    uint64_t srvid);
void verify_ctdb_message_data(union ctdb_message_data *md,
			      union ctdb_message_data *md2, uint64_t srvid);

void fill_ctdb_req_message(TALLOC_CTX *mem_ctx, struct ctdb_req_message *c,
			   uint64_t srvid);
void verify_ctdb_req_message(struct ctdb_req_message *c,
			     struct ctdb_req_message *c2);

void fill_ctdb_req_message_data(TALLOC_CTX *mem_ctx,
				struct ctdb_req_message_data *c);
void verify_ctdb_req_message_data(struct ctdb_req_message_data *c,
				  struct ctdb_req_message_data *c2);

void fill_ctdb_req_keepalive(TALLOC_CTX *mem_ctx,
			     struct ctdb_req_keepalive *c);
void verify_ctdb_req_keepalive(struct ctdb_req_keepalive *c,
			       struct ctdb_req_keepalive *c2);

void fill_ctdb_req_tunnel(TALLOC_CTX *mem_ctx, struct ctdb_req_tunnel *c);
void verify_ctdb_req_tunnel(struct ctdb_req_tunnel *c,
			    struct ctdb_req_tunnel *c2);

#endif /* __CTDB_PROTOCOL_COMMON_CTDB_H__ */
