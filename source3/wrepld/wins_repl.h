/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Jean François Micouleau      1998-2002.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OPCODE_NON_NBT	0x00007800

/* the messages */
#define MESSAGE_TYPE_START_ASSOC_REQUEST	0
#define MESSAGE_TYPE_START_ASSOC_REPLY		1
#define MESSAGE_TYPE_STOP_ASSOC			2
#define MESSAGE_TYPE_REPLICATE			3

/* the replication sub-message */
#define MESSAGE_REP_ADD_VERSION_REQUEST		0
#define MESSAGE_REP_ADD_VERSION_REPLY		1
#define MESSAGE_REP_SEND_ENTRIES_REQUEST	2
#define MESSAGE_REP_SEND_ENTRIES_REPLY		3
#define MESSAGE_REP_UPDATE_NOTIFY_REQUEST	4

/* stop reasons */
#define STOP_REASON_USER_REASON			0
#define STOP_REASON_AUTH_FAILED			1
#define STOP_REASON_INCOMPLETE_VERSION		2
#define STOP_REASON_BUG_CHECK			3
#define STOP_REASON_MESSAGE_ERROR		4


typedef struct _WINS_OWNER {
	struct in_addr address;
	SMB_BIG_UINT max_version;
	SMB_BIG_UINT min_version;
	int type;
	time_t last_pull;
	time_t last_push;
} WINS_OWNER;

typedef struct _WINS_NAME {
	int name_len; /* always 0x11 */
	char name[16];
	char type;
	int empty;
	int name_flag;
	int group_flag;
	SMB_BIG_UINT id;
	int num_ip;
	struct in_addr owner;
	struct in_addr *others;
	int foo; /* 0xffffff */
} WINS_NAME;
	
typedef struct _WINS_PARTNERS
{
	int client_assoc;
	int server_assoc;
	BOOL pull_partner;
	BOOL push_partner;
	struct in_addr partner_server;
	struct in_addr other_server;
} WINS_PARTNER;

typedef struct _generic_header{
	int data_size;
	int opcode;
	int assoc_ctx;
	int mess_type;
} generic_header;

typedef struct _START_ASSOC_REQUEST {
	int assoc_ctx;
	int min_ver;
	int maj_ver;
} START_ASSOC_REQUEST;

typedef struct _START_ASSOC_REPLY {
	int assoc_ctx;
	int min_ver;
	int maj_ver;
} START_ASSOC_REPLY;

typedef struct _STOP_ASSOC {
	int reason;
} STOP_ASSOC;

typedef struct _AVMT_REP {
	int partner_count;
	WINS_OWNER *wins_owner;
	struct in_addr initiating_wins_server;
} AVMT_REP;

typedef struct _SEND_ENTRIES_REQUEST {
	WINS_OWNER wins_owner;
} SEND_ENTRIES_REQUEST;

typedef struct _SEND_ENTRIES_REPLY {
	int max_names;
	WINS_NAME *wins_name;	
} SEND_ENTRIES_REPLY;

typedef struct  _UPDATE_NOTIFY_REQUEST {
	int partner_count;
	WINS_OWNER *wins_owner;	
	struct in_addr initiating_wins_server;
} UPDATE_NOTIFY_REQUEST;

typedef struct _REPLICATE {
	int msg_type;
	
	AVMT_REP avmt_rep;
	SEND_ENTRIES_REQUEST se_rq;
	SEND_ENTRIES_REPLY se_rp;
	UPDATE_NOTIFY_REQUEST un_rq;
} REPLICATE;


typedef struct _GENERIC_PACKET {
	int fd;

	generic_header header;

	START_ASSOC_REQUEST sa_rq;
	START_ASSOC_REPLY sa_rp;
	STOP_ASSOC so;
	REPLICATE rep;
} GENERIC_PACKET;

struct wins_packet_struct
{
	struct wins_packet_struct *next;
	struct wins_packet_struct *prev;
	BOOL stop_packet;
	int fd;
	time_t timestamp;
	GENERIC_PACKET *packet;
};

struct BUFFER {
	char *buffer;
	int offset;
	int length;
};



#include "wrepld_proto.h"

