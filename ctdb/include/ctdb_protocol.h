/*
   ctdb database library

   Copyright (C) Andrew Tridgell  2006

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

#ifndef _CTDB_PROTOCOL_H
#define _CTDB_PROTOCOL_H

#include <sys/socket.h>
#include "protocol/protocol.h"

/* define ctdb port number */
#define CTDB_PORT 4379

/* we must align packets to ensure ctdb works on all architectures (eg. sparc) */
#define CTDB_DS_ALIGNMENT 8

/*
  structure passed to a ctdb call backend function
*/
struct ctdb_call_info {
	TDB_DATA key;          /* record key */
	struct ctdb_ltdb_header *header;
	TDB_DATA record_data;  /* current data in the record */
	TDB_DATA *new_data;    /* optionally updated record data */
	TDB_DATA *call_data;   /* optionally passed from caller */
	TDB_DATA *reply_data;  /* optionally returned by function */
	uint32_t status;       /* optional reply status - defaults to zero */
};

/*
  ctdb flags
*/
#define CTDB_FLAG_TORTURE      (1<<1)

struct ctdb_script_list_old {
	uint32_t num_scripts;
	struct ctdb_script scripts[1];
};

/* Mapping from enum to names. */
extern const char *ctdb_eventscript_call_names[];

/*
  packet structures
*/
struct ctdb_req_call_old {
	struct ctdb_req_header hdr;
	uint32_t flags;
	uint32_t db_id;
	uint32_t callid;
	uint32_t hopcount;
	uint32_t keylen;
	uint32_t calldatalen;
	uint8_t data[1]; /* key[] followed by calldata[] */
};

struct ctdb_reply_call_old {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_reply_error_old {
	struct ctdb_req_header hdr;
	uint32_t status;
	uint32_t msglen;
	uint8_t  msg[1];
};

struct ctdb_req_dmaster_old {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t dmaster;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_reply_dmaster_old {
	struct ctdb_req_header hdr;
	uint32_t db_id;
	uint64_t rsn;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

struct ctdb_req_message_old {
	struct ctdb_req_header hdr;
	uint64_t srvid;
	uint32_t datalen;
	uint8_t data[1];
};

struct ctdb_req_control_old {
	struct ctdb_req_header hdr;
	uint32_t opcode;
	uint32_t pad;
	uint64_t srvid;
	uint32_t client_id;
	uint32_t flags;
	uint32_t datalen;
	uint8_t data[1];
};

struct ctdb_reply_control_old {
	struct ctdb_req_header hdr;
	int32_t  status;
	uint32_t datalen;
	uint32_t errorlen;
	uint8_t data[1];
};

struct ctdb_req_keepalive_old {
	struct ctdb_req_header hdr;
	uint32_t version;
	uint32_t uptime;
};

struct ctdb_req_tunnel_old {
	struct ctdb_req_header hdr;
	uint64_t tunnel_id;
	uint32_t flags;
	uint32_t datalen;
	uint8_t data[1];
};

/*
   Structure used for a nodemap. 
   The nodemap is the structure containing a list of all nodes
   known to the cluster and their associated flags.
*/
struct ctdb_node_map_old {
	uint32_t num;
	struct ctdb_node_and_flags nodes[1];
};

struct ctdb_public_ip_list_old {
	uint32_t num;
	struct ctdb_public_ip ips[1];
};

/*
  structure used to pass record data between the child and parent
 */
struct ctdb_rec_data_old {
	uint32_t length;
	uint32_t reqid;
	uint32_t keylen;
	uint32_t datalen;
	uint8_t  data[1];
};

/*
 * wire format for statistics history
 */
struct ctdb_statistics_list_old {
	uint32_t num;
	struct ctdb_statistics stats[1];
};

/*
 * db statistics
 */
struct ctdb_db_statistics_old {
	struct {
		uint32_t num_calls;
		uint32_t num_current;
		uint32_t num_pending;
		uint32_t num_failed;
		struct ctdb_latency_counter latency;
		uint32_t buckets[MAX_COUNT_BUCKETS];
	} locks;
	struct {
		struct ctdb_latency_counter latency;
	} vacuum;
	uint32_t db_ro_delegations;
	uint32_t db_ro_revokes;
	uint32_t hop_count_bucket[MAX_COUNT_BUCKETS];
	uint32_t num_hot_keys;
	struct {
		uint32_t count;
		TDB_DATA key;
	} hot_keys[MAX_HOT_KEYS];
	char hot_keys_wire[1];
};

/* 
   a wire representation of the vnn map
 */
struct ctdb_vnn_map_wire {
	uint32_t generation;
	uint32_t size;
	uint32_t map[1];
};

struct ctdb_notify_data_old {
	uint64_t srvid;
	uint32_t len;
	uint8_t notify_data[1];
};

/* table that contains a list of all dbids on a node
 */
struct ctdb_dbid_map_old {
	uint32_t num;
	struct ctdb_dbid dbs[1];
};

/* the list of tcp tickles used by get/set tcp tickle list */
struct ctdb_tickle_list_old {
	ctdb_sock_addr addr;
	uint32_t num;
	struct ctdb_connection connections[1];
};

/*
  struct holding a ctdb_sock_addr and an interface name,
  used to add/remove public addresses and grat arp
 */
struct ctdb_addr_info_old {
	ctdb_sock_addr addr;
	uint32_t mask;
	uint32_t len;
	char iface[1];
};

/* structure used for sending lists of records */
struct ctdb_marshall_buffer {
	uint32_t db_id;
	uint32_t count;
	uint8_t data[1];
};

/*
  structure for setting a tunable
 */
struct ctdb_tunable_old {
	uint32_t value;
	uint32_t length;
	uint8_t  name[1];
};

/*
  structure for getting a tunable
 */
struct ctdb_control_get_tunable {
	uint32_t length;
	uint8_t  name[1];
};

/*
  structure for listing tunables
 */
struct ctdb_control_list_tunable {
	uint32_t length;
	/* returns a : separated list of tunable names */
	uint8_t  data[1];
};


struct ctdb_public_ip_info_old {
	struct ctdb_public_ip ip;
	uint32_t active_idx;
	uint32_t num;
	struct ctdb_iface ifaces[1];
};

struct ctdb_iface_list_old {
	uint32_t num;
	struct ctdb_iface ifaces[1];
};

/**
 * structure to pass to a schedule_for_deletion_control
 */
struct ctdb_control_schedule_for_deletion {
	uint32_t db_id;
	struct ctdb_ltdb_header hdr;
	uint32_t keylen;
	uint8_t key[1]; /* key[] */
};

#endif
