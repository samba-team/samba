/*
   CTDB event daemon protocol
   Based on eventd code

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

#ifndef __CTDB_EVENT_PROTOCOL_H__
#define __CTDB_EVENT_PROTOCOL_H__

#define CTDB_EVENT_PROTOCOL_VERSION	1

enum ctdb_event_script_action {
	CTDB_EVENT_SCRIPT_DISABLE = 0,
	CTDB_EVENT_SCRIPT_ENABLE  = 1,
};

enum ctdb_event_command {
	CTDB_EVENT_CMD_RUN     = 1,
	CTDB_EVENT_CMD_STATUS  = 2,
	CTDB_EVENT_CMD_SCRIPT  = 3,
	CTDB_EVENT_CMD_MAX     = 4,
};

struct ctdb_event_script {
	const char *name;
	struct timeval begin;
	struct timeval end;
	int result;
	const char *output;
};

struct ctdb_event_script_list {
	int num_scripts;
	struct ctdb_event_script *script;
};

#define CTDB_EVENT_RUN_ALL	1

struct ctdb_event_request_run {
	const char *component;
	const char *event;
	const char *args;
	uint32_t timeout;
	uint32_t flags;
};

struct ctdb_event_request_status {
	const char *component;
	const char *event;
};

struct ctdb_event_request_script {
	const char *component;
	const char *script;
	enum ctdb_event_script_action action;
};

struct ctdb_event_reply_status {
	int32_t summary;
	struct ctdb_event_script_list *script_list;
};

struct ctdb_event_header {
	uint32_t length;
	uint32_t version;
	uint32_t reqid;
};

struct ctdb_event_request {
	enum ctdb_event_command cmd;
	union {
		struct ctdb_event_request_run *run;
		struct ctdb_event_request_status *status;
		struct ctdb_event_request_script *script;
	} data;
};

struct ctdb_event_reply {
	enum ctdb_event_command cmd;
	int32_t result;
	union {
		struct ctdb_event_reply_status *status;
	} data;
};

#endif /* __CTDB_EVENT_PROTOCOL_H__ */
