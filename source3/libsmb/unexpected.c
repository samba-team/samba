/*
   Unix SMB/CIFS implementation.
   handle unexpected packets
   Copyright (C) Andrew Tridgell 2000

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

#include "includes.h"

static struct tdb_wrap *tdbd = NULL;

/* the key type used in the unexpected packet database */
struct unexpected_key {
	enum packet_type packet_type;
	time_t timestamp;
	int count;
};

struct pending_unexpected {
	struct pending_unexpected *prev, *next;
	enum packet_type packet_type;
	int id;
	time_t timeout;
};

static struct pending_unexpected *pu_list;

/****************************************************************************
 This function is called when nmbd has received an unexpected packet.
 It checks against the list of outstanding packet transaction id's
 to see if it should be stored in the unexpected.tdb.
**************************************************************************/

static struct pending_unexpected *find_unexpected_packet(struct packet_struct *p)
{
	struct pending_unexpected *pu;

	if (!p) {
		return NULL;
	}

	for (pu = pu_list; pu; pu = pu->next) {
		if (pu->packet_type == p->packet_type) {
			int id = (p->packet_type == DGRAM_PACKET) ?
				p->packet.dgram.header.dgm_id :
				p->packet.nmb.header.name_trn_id;
			if (id == pu->id) {
				DEBUG(10,("find_unexpected_packet: found packet "
					"with id = %d\n", pu->id ));
				return pu;
			}
		}
	}

	return NULL;
}


/****************************************************************************
 This function is called when nmbd has been given a packet to send out.
 It stores a list of outstanding packet transaction id's and the timeout
 when they should be removed.
**************************************************************************/

bool store_outstanding_send_packet(struct packet_struct *p)
{
	struct pending_unexpected *pu = NULL;

	if (!p) {
		return false;
	}

	pu = find_unexpected_packet(p);
	if (pu) {
		/* This is a resend, and we haven't received a
		   reply yet ! Ignore it. */
		return false;
	}

	pu = SMB_MALLOC_P(struct pending_unexpected);
	if (!pu || !p) {
		return false;
	}

	ZERO_STRUCTP(pu);
	pu->packet_type = p->packet_type;
	pu->id = (p->packet_type == DGRAM_PACKET) ?
			p->packet.dgram.header.dgm_id :
			p->packet.nmb.header.name_trn_id;
	pu->timeout = time(NULL) + 15;

	DLIST_ADD_END(pu_list, pu, struct pending_unexpected *);

	DEBUG(10,("store_outstanding_unexpected_packet: storing packet "
		"with id = %d\n", pu->id ));

	return true;
}

/****************************************************************************
 Return true if this is a reply to a packet we were requested to send.
**************************************************************************/

bool is_requested_send_packet(struct packet_struct *p)
{
	return (find_unexpected_packet(p) != NULL);
}

/****************************************************************************
 This function is called when nmbd has received an unexpected packet.
 It checks against the list of outstanding packet transaction id's
 to see if it should be stored in the unexpected.tdb. Don't store if
 not found.
**************************************************************************/

static bool should_store_unexpected_packet(struct packet_struct *p)
{
	struct pending_unexpected *pu = find_unexpected_packet(p);

	if (!pu) {
		return false;
	}

	/* Remove the outstanding entry. */
	DLIST_REMOVE(pu_list, pu);
	SAFE_FREE(pu);
	return true;
}

/****************************************************************************
 All unexpected packets are passed in here, to be stored in a unexpected
 packet database. This allows nmblookup and other tools to receive packets
 erroneously sent to the wrong port by broken MS systems.
**************************************************************************/

void unexpected_packet(struct packet_struct *p)
{
	static int count;
	TDB_DATA kbuf, dbuf;
	struct unexpected_key key;
	char buf[1024];
	int len=0;
	uint32_t enc_ip;

	if (!should_store_unexpected_packet(p)) {
		DEBUG(10,("Not storing unexpected packet\n"));
		return;
	}

	DEBUG(10,("unexpected_packet: storing packet\n"));

	if (!tdbd) {
		tdbd = tdb_wrap_open(talloc_autofree_context(),
				     lock_path("unexpected.tdb"), 0,
				     TDB_CLEAR_IF_FIRST|TDB_DEFAULT|TDB_INCOMPATIBLE_HASH,
				     O_RDWR | O_CREAT, 0644);
		if (!tdbd) {
			DEBUG(0,("Failed to open unexpected.tdb\n"));
			return;
		}
	}

	memset(buf,'\0',sizeof(buf));

	/* Encode the ip addr and port. */
	enc_ip = ntohl(p->ip.s_addr);
	SIVAL(buf,0,enc_ip);
	SSVAL(buf,4,p->port);

	len = build_packet(&buf[6], sizeof(buf)-6, p) + 6;

	ZERO_STRUCT(key);	/* needed for potential alignment */

	key.packet_type = p->packet_type;
	key.timestamp = p->timestamp;
	key.count = count++;

	kbuf.dptr = (uint8_t *)&key;
	kbuf.dsize = sizeof(key);
	dbuf.dptr = (uint8_t *)buf;
	dbuf.dsize = len;

	tdb_store(tdbd->tdb, kbuf, dbuf, TDB_REPLACE);
}


static time_t lastt;

/****************************************************************************
 Delete the record if it is too old.
**************************************************************************/

static int traverse_fn(TDB_CONTEXT *ttdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state)
{
	struct unexpected_key key;

	if (kbuf.dsize != sizeof(key)) {
		tdb_delete(ttdb, kbuf);
	}

	memcpy(&key, kbuf.dptr, sizeof(key));

	if (lastt - key.timestamp > NMBD_UNEXPECTED_TIMEOUT) {
		tdb_delete(ttdb, kbuf);
	}

	return 0;
}


/****************************************************************************
 Delete all old unexpected packets.
**************************************************************************/

void clear_unexpected(time_t t)
{
	struct pending_unexpected *pu, *pu_next;

	for (pu = pu_list; pu; pu = pu_next) {
		pu_next = pu->next;
		if (pu->timeout < t) {
			DLIST_REMOVE(pu_list, pu);
		}
	}

	if (!tdbd) return;

	if ((lastt != 0) && (t < lastt + NMBD_UNEXPECTED_TIMEOUT))
		return;

	lastt = t;

	tdb_traverse(tdbd->tdb, traverse_fn, NULL);
}

struct receive_unexpected_state {
	struct packet_struct *matched_packet;
	int match_id;
	enum packet_type match_type;
	const char *match_name;
};

/****************************************************************************
 tdb traversal fn to find a matching 137 packet.
**************************************************************************/

static int traverse_match(TDB_CONTEXT *ttdb, TDB_DATA kbuf, TDB_DATA dbuf,
			  void *private_data)
{
	struct receive_unexpected_state *state =
		(struct receive_unexpected_state *)private_data;
	struct unexpected_key key;
	struct in_addr ip;
	uint32_t enc_ip;
	int port;
	struct packet_struct *p;

	if (kbuf.dsize != sizeof(key)) {
		return 0;
	}

	memcpy(&key, kbuf.dptr, sizeof(key));

	if (key.packet_type != state->match_type) return 0;

	if (dbuf.dsize < 6) {
		return 0;
	}

	/* Decode the ip addr and port. */
	enc_ip = IVAL(dbuf.dptr,0);
	ip.s_addr = htonl(enc_ip);
	port = SVAL(dbuf.dptr,4);

	p = parse_packet((char *)&dbuf.dptr[6],
			dbuf.dsize-6,
			state->match_type,
			ip,
			port);
	if (!p)
		return 0;

	if ((state->match_type == NMB_PACKET &&
	     p->packet.nmb.header.name_trn_id == state->match_id) ||
	    (state->match_type == DGRAM_PACKET &&
	     match_mailslot_name(p, state->match_name) &&
	     p->packet.dgram.header.dgm_id == state->match_id)) {
		state->matched_packet = p;
		tdb_delete(ttdb, kbuf);
		return -1;
	}

	free_packet(p);

	return 0;
}

/****************************************************************************
 Check for a particular packet in the unexpected packet queue.
**************************************************************************/

struct packet_struct *receive_unexpected(enum packet_type packet_type, int id,
					 const char *mailslot_name)
{
	struct tdb_wrap *tdb2;
	struct receive_unexpected_state state;

	tdb2 = tdb_wrap_open(talloc_tos(), lock_path("unexpected.tdb"), 0, 0,
			     O_RDWR, 0);
	if (!tdb2) return NULL;

	state.matched_packet = NULL;
	state.match_id = id;
	state.match_type = packet_type;
	state.match_name = mailslot_name;

	tdb_traverse(tdb2->tdb, traverse_match, &state);

	TALLOC_FREE(tdb2);

	return state.matched_packet;
}
