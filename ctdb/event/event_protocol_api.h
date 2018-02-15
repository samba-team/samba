/*
   CTDB event daemon protocol

   Copyright (C) Amitay Isaacs  2018

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

#ifndef __CTDB_EVENT_PROTOCOL_API_H__
#define __CTDB_EVENT_PROTOCOL_API_H__

#include <talloc.h>

#include "event/event_protocol.h"

/* From event/event_protocol.c */

int ctdb_event_header_extract(uint8_t *buf,
			      size_t buflen,
			      struct ctdb_event_header *h);

size_t ctdb_event_request_len(struct ctdb_event_header *h,
			      struct ctdb_event_request *in);
int ctdb_event_request_push(struct ctdb_event_header *h,
			    struct ctdb_event_request *in,
			    uint8_t *buf,
			    size_t *buflen);
int ctdb_event_request_pull(uint8_t *buf,
			    size_t buflen,
			    struct ctdb_event_header *h,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_event_request **out);

size_t ctdb_event_reply_len(struct ctdb_event_header *h,
			    struct ctdb_event_reply *in);
int ctdb_event_reply_push(struct ctdb_event_header *h,
			  struct ctdb_event_reply *in,
			  uint8_t *buf,
			  size_t *buflen);
int ctdb_event_reply_pull(uint8_t *buf,
			  size_t buflen,
			  struct ctdb_event_header *h,
			  TALLOC_CTX *mem_ctx,
			  struct ctdb_event_reply **out);

/* From event/event_protocol_util.c */

const char *ctdb_event_command_to_string(enum ctdb_event_command cmd);

#endif /* __CTDB_EVENT_PROTOCOL_API_H__ */
