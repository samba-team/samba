/*
   protocol tests - eventd protocol

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

#ifndef __CTDB_PROTOCOL_COMMON_EVENT_H__
#define __CTDB_PROTOCOL_COMMON_EVENT_H__

#include "replace.h"
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

#include "protocol/protocol.h"

void fill_ctdb_event_request_run(TALLOC_CTX *mem_ctx,
				 struct ctdb_event_request_run *p);
void verify_ctdb_event_request_run(struct ctdb_event_request_run *p1,
				   struct ctdb_event_request_run *p2);

void fill_ctdb_event_request_status(TALLOC_CTX *mem_ctx,
				    struct ctdb_event_request_status *p);
void verify_ctdb_event_request_status(struct ctdb_event_request_status *p1,
				      struct ctdb_event_request_status *p2);

void fill_ctdb_event_request_script_enable(TALLOC_CTX *mem_ctx,
				struct ctdb_event_request_script_enable *p);
void verify_ctdb_event_request_script_enable(
				struct ctdb_event_request_script_enable *p1,
				struct ctdb_event_request_script_enable *p2);

void fill_ctdb_event_request_script_disable(TALLOC_CTX *mem_ctx,
				struct ctdb_event_request_script_disable *p);
void verify_ctdb_event_request_script_disable(
				struct ctdb_event_request_script_disable *p1,
				struct ctdb_event_request_script_disable *p2);

void fill_ctdb_event_reply_status(TALLOC_CTX *mem_ctx,
				  struct ctdb_event_reply_status *p);
void verify_ctdb_event_reply_status(struct ctdb_event_reply_status *p1,
				    struct ctdb_event_reply_status *p2);

void fill_ctdb_event_reply_script_list(TALLOC_CTX *mem_ctx,
				       struct ctdb_event_reply_script_list *p);
void verify_ctdb_event_reply_script_list(
				struct ctdb_event_reply_script_list *p1,
				struct ctdb_event_reply_script_list *p2);

void fill_ctdb_event_request_data(TALLOC_CTX *mem_ctx,
				  struct ctdb_event_request_data *r,
				  uint32_t command);
void verify_ctdb_event_request_data(struct ctdb_event_request_data *r,
				    struct ctdb_event_request_data *r2);

void fill_ctdb_event_reply_data(TALLOC_CTX *mem_ctx,
				struct ctdb_event_reply_data *r,
				uint32_t command);
void verify_ctdb_event_reply_data(struct ctdb_event_reply_data *r,
				  struct ctdb_event_reply_data *r2);

void fill_ctdb_event_request(TALLOC_CTX *mem_ctx,
			     struct ctdb_event_request *r, uint32_t command);
void verify_ctdb_event_request(struct ctdb_event_request *r,
			       struct ctdb_event_request *r2);

void fill_ctdb_event_reply(TALLOC_CTX *mem_ctx, struct ctdb_event_reply *r,
			   uint32_t command);
void verify_ctdb_event_reply(struct ctdb_event_reply *r,
			     struct ctdb_event_reply *r2);

#endif /* __CTDB_PROTOCOL_COMMON_EVENT_H__ */
