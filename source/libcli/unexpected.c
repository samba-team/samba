/* 
   Unix SMB/CIFS implementation.
   handle unexpected packets
   Copyright (C) Andrew Tridgell 2000
   
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

#include "includes.h"

static struct tdb_wrap *tdbd = NULL;

/* the key type used in the unexpeceted packet database */
struct unexpected_key {
	enum packet_type packet_type;
	time_t timestamp;
	int count;
};



/****************************************************************************
 all unexpected packets are passed in here, to be stored in a unexpected
 packet database. This allows nmblookup and other tools to receive packets
 erroneoously sent to the wrong port by broken MS systems
  **************************************************************************/
void unexpected_packet(struct packet_struct *p)
{
	static int count;
	TDB_DATA kbuf, dbuf;
	struct unexpected_key key;
	char buf[1024];
	int len=0;
	TALLOC_CTX *mem_ctx;

	if (!tdbd) {
		mem_ctx = talloc_init("receive_unexpected");
		if (!mem_ctx) return;
		tdbd = tdb_wrap_open(NULL, lock_path(mem_ctx, "unexpected.tdb"), 0, 
				     TDB_DEFAULT,
				     O_RDWR | O_CREAT, 0644);
		talloc_destroy(mem_ctx);
		if (!tdbd) {
			return;
		}
	}

	memset(buf,'\0',sizeof(buf));
	
	len = build_packet(buf, p);

	key.packet_type = p->packet_type;
	key.timestamp = p->timestamp;
	key.count = count++;

	kbuf.dptr = (char *)&key;
	kbuf.dsize = sizeof(key);
	dbuf.dptr = buf;
	dbuf.dsize = len;

	tdb_store(tdbd->tdb, kbuf, dbuf, TDB_REPLACE);
}


static time_t lastt;

/****************************************************************************
delete the record if it is too old
  **************************************************************************/
static int traverse_fn(TDB_CONTEXT *ttdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state)
{
	struct unexpected_key key;

	memcpy(&key, kbuf.dptr, sizeof(key));

	if (lastt - key.timestamp > NMBD_UNEXPECTED_TIMEOUT) {
		tdb_delete(ttdb, kbuf);
	}

	return 0;
}


/****************************************************************************
delete all old unexpected packets
  **************************************************************************/
void clear_unexpected(time_t t)
{
	if (!tdbd) return;

	if ((lastt != 0) && (t < lastt + NMBD_UNEXPECTED_TIMEOUT))
		return;

	lastt = t;

	tdb_traverse(tdbd->tdb, traverse_fn, NULL);
}


static struct packet_struct *matched_packet;
static int match_id;
static enum packet_type match_type;
static const char *match_name;

/****************************************************************************
tdb traversal fn to find a matching 137 packet
  **************************************************************************/
static int traverse_match(TDB_CONTEXT *ttdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state)
{
	struct unexpected_key key;
	struct packet_struct *p;

	memcpy(&key, kbuf.dptr, sizeof(key));

	if (key.packet_type != match_type) return 0;

	p = parse_packet(dbuf.dptr, dbuf.dsize, match_type);

	if ((match_type == NMB_PACKET && 
	     p->packet.nmb.header.name_trn_id == match_id) ||
	    (match_type == DGRAM_PACKET && 
	     match_mailslot_name(p, match_name))) {
		matched_packet = p;
		return -1;
	}

	free_packet(p);

	return 0;
}


/****************************************************************************
check for a particular packet in the unexpected packet queue
  **************************************************************************/
struct packet_struct *receive_unexpected(enum packet_type packet_type, int id, 
					 const char *mailslot_name)
{
	struct tdb_wrap *tdb2;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("receive_unexpected");
	if (!mem_ctx) return NULL;
	tdb2 = tdb_wrap_open(mem_ctx, lock_path(mem_ctx, "unexpected.tdb"), 0, 0, O_RDONLY, 0);
	if (!tdb2) {
		talloc_destroy(mem_ctx);
		return NULL;
	}

	matched_packet = NULL;
	match_id = id;
	match_type = packet_type;
	match_name = mailslot_name;

	tdb_traverse(tdb2->tdb, traverse_match, NULL);

	talloc_destroy(mem_ctx);

	return matched_packet;
}
