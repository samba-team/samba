/* 
   Unix SMB/CIFS implementation.
   process incoming packets - main loop
   Copyright (C) Jean François Micouleau      1998-2002.
   
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
#include "wins_repl.h"

extern fd_set *listen_set;
extern int listen_number;
extern int *sock_array;

WINS_OWNER global_wins_table[64][64];
int partner_count;

TALLOC_CTX *mem_ctx;

#define WINS_LIST "wins.tdb"
#define INFO_VERSION	"INFO/version"
#define INFO_COUNT	"INFO/num_entries"
#define INFO_ID_HIGH	"INFO/id_high"
#define INFO_ID_LOW	"INFO/id_low"
#define ENTRY_PREFIX 	"ENTRY/"


/*******************************************************************
fill the header of a reply.
********************************************************************/
static void fill_header(GENERIC_PACKET *g, int opcode, int ctx, int mess)
{
	if (g==NULL)
		return;

	g->header.opcode=opcode;
	g->header.assoc_ctx=ctx;
	g->header.mess_type=mess;
}

/*******************************************************************
dump the global table, that's a debug code.
********************************************************************/
static void dump_global_table(void)
{
	int i,j;
	
	for (i=0;i<partner_count;i++) {
		DEBUG(10,("\n%d ", i));
		for (j=0; global_wins_table[i][j].address.s_addr!=0; j++)
			DEBUG(10,("%s:%d \t", inet_ntoa(global_wins_table[i][j].address),
				(int)global_wins_table[i][j].max_version));
	}
	DEBUG(10,("\n"));
}

/*******************************************************************
start association
********************************************************************/
static void start_assoc_process(GENERIC_PACKET *q, GENERIC_PACKET *r)
{
	/*
	 * add this request to our current wins partners list
	 * this list is used to know with who we are in contact
	 *
	 */
	r->sa_rp.assoc_ctx=time(NULL);
	fill_header(r, OPCODE_NON_NBT, q->sa_rq.assoc_ctx, MESSAGE_TYPE_START_ASSOC_REPLY);

	/* reply we are a NT4 server */
	
	/* w2K is min=2, maj=5 */
	
	r->sa_rp.min_ver=1;
	r->sa_rp.maj_ver=1;

	add_partner(r->sa_rp.assoc_ctx, q->sa_rq.assoc_ctx, False, False);
}

/*******************************************************************
start association reply
********************************************************************/
static void start_assoc_reply(GENERIC_PACKET *q, GENERIC_PACKET *r)
{
	int i;

	/* check if we have already registered this client */
	if (!check_partner(q->header.assoc_ctx)) {
		DEBUG(0,("start_assoc_reply: unknown client\n"));
		stop_packet(q, r, STOP_REASON_USER_REASON);
		return;
	}

	if (!update_server_partner(q->header.assoc_ctx, q->sa_rp.assoc_ctx)) {
		DEBUG(0,("start_assoc_reply: can't update server ctx\n"));
		stop_packet(q, r, STOP_REASON_USER_REASON);
		return;
	}

	/* if pull, request map table */	
	if (check_pull_partner(q->header.assoc_ctx)) {
		fill_header(r, OPCODE_NON_NBT, get_server_assoc(q->header.assoc_ctx), MESSAGE_TYPE_REPLICATE);

		r->rep.msg_type=MESSAGE_REP_ADD_VERSION_REQUEST;
		DEBUG(5,("start_assoc_reply: requesting map table\n"));

		return;
	}

	/* if push, send our table */
	if (check_push_partner(q->header.assoc_ctx)) {
		fill_header(r, OPCODE_NON_NBT, get_server_assoc(q->header.assoc_ctx), MESSAGE_TYPE_REPLICATE);
		r->rep.msg_type=MESSAGE_REP_UPDATE_NOTIFY_REQUEST;
		r->rep.un_rq.partner_count=partner_count;
		
		r->rep.un_rq.wins_owner=(WINS_OWNER *)talloc(mem_ctx, partner_count*sizeof(WINS_OWNER));
		if (r->rep.un_rq.wins_owner==NULL) {
			DEBUG(0,("start_assoc_reply: can't alloc memory\n"));
			stop_packet(q, r, STOP_REASON_USER_REASON);
			return;
		}

		for (i=0; i<partner_count; i++)
			r->rep.un_rq.wins_owner[i]=global_wins_table[0][i];
		
		DEBUG(5,("start_assoc_reply: sending update table\n"));
		return;
	}
	
	/* neither push/pull, stop */
	/* we should not come here */
	DEBUG(0,("we have a partner which is neither push nor pull !\n"));
	stop_packet(q, r, STOP_REASON_USER_REASON);
}

/****************************************************************************
initialise and fill the in-memory partner table.
****************************************************************************/
int init_wins_partner_table(void)
{
	int i=1,j=0,k;
	char **partner = str_list_make(lp_wins_partners(), NULL);

	if (partner==NULL) {
		DEBUG(0,("wrepld: no partner list in smb.conf, exiting\n"));
		exit_server("normal exit");
		return(0);
	}

	DEBUG(4, ("init_wins_partner_table: partners: %s\n", lp_wins_partners()));

	global_wins_table[0][0].address=*iface_n_ip(0);
	global_wins_table[0][0].max_version=0;
	global_wins_table[0][0].min_version=0;
	global_wins_table[0][0].type=0;

	while (partner[j]!=NULL) {
		DEBUG(3,("init_wins_partner_table, adding partner: %s\n", partner[j]));
		
		global_wins_table[0][i].address=*interpret_addr2(partner[j]);
		global_wins_table[0][i].max_version=0;
		global_wins_table[0][i].min_version=0;
		global_wins_table[0][i].type=0;
		global_wins_table[0][i].last_pull=0;
		global_wins_table[0][i].last_push=0;

		i++;
		j++;
	}
	
	for (k=1; k<i;k++)
		for (j=0; j<i; j++)
			global_wins_table[k][j]=global_wins_table[0][j];
	
	str_list_free (&partner);
	
	return i;
}

/****************************************************************************
read the last ID from the wins tdb file.
****************************************************************************/
static void get_our_last_id(WINS_OWNER *wins_owner)
{
	TDB_CONTEXT *tdb;

	tdb = tdb_open_log(lock_path(WINS_LIST), 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (!tdb) {
		DEBUG(2,("get_our_last_id: Can't open wins database file %s. Error was %s\n", WINS_LIST, strerror(errno) ));
		return;
	}
	
	wins_owner->max_version=((SMB_BIG_UINT)tdb_fetch_int32(tdb, INFO_ID_HIGH))<<32 | 
				 (SMB_BIG_UINT)tdb_fetch_int32(tdb, INFO_ID_LOW);

	tdb_close(tdb);
}

/****************************************************************************
send the list of wins server we know.
****************************************************************************/
static void send_version_number_map_table(GENERIC_PACKET *q, GENERIC_PACKET *r)
{
	int i;
	int s_ctx=get_server_assoc(q->header.assoc_ctx);

	if (s_ctx==0) {
		DEBUG(5, ("send_version_number_map_table: request for a partner not in our table\n"));
		stop_packet(q, r, STOP_REASON_USER_REASON);
		return;
	}

	/*
	 * return an array of wins servers, we are partner with.
	 * each entry contains the IP address and the version info
	 * version: ID of the last entry we've got
	 */

	/* the first wins server must be self */

	/*
	 * get our last ID from the wins database
	 * it can have been updated since last read
	 * as nmbd got registration/release.
	 */ 
	get_our_last_id(&global_wins_table[0][0]);

	r->rep.avmt_rep.wins_owner=(WINS_OWNER *)talloc(mem_ctx, partner_count*sizeof(WINS_OWNER));
	if (r->rep.avmt_rep.wins_owner==NULL) {
		stop_packet(q, r, STOP_REASON_USER_REASON);
		return;
	}
	
	DEBUG(5,("send_version_number_map_table: partner_count: %d\n", partner_count));

	for (i=0; i<partner_count; i++) {
		DEBUG(5,("send_version_number_map_table, partner: %d -> %s, \n", i, inet_ntoa(global_wins_table[0][i].address)));
		r->rep.avmt_rep.wins_owner[i]=global_wins_table[0][i];
	}
	
	r->rep.msg_type=1;
	r->rep.avmt_rep.partner_count=partner_count;
	r->rep.avmt_rep.initiating_wins_server.s_addr=0; /* blatant lie, NT4/w2K do the same ! */
	fill_header(r, OPCODE_NON_NBT, s_ctx, MESSAGE_TYPE_REPLICATE);
}

/****************************************************************************
for a given partner, ask it to send entries we don't have.
****************************************************************************/
static BOOL check_partners_and_send_entries(GENERIC_PACKET *q, GENERIC_PACKET *r, int partner)
{
	int server;
	int other;
	SMB_BIG_UINT temp;
	SMB_BIG_UINT current;


	/*
	 * we check if our partner has more records than us.
	 * we need to check more than our direct partners as
	 * we can have this case:
	 * us: A, partners: B,C, indirect partner: D
	 * A<->B, A<->C, B<->D, C<->D
	 *
	 * So if we're talking to B, we need to check if between
	 * B and C, which one have more records about D.
	 * and also check if we don't already have the records.
	 */


	 /* check all servers even indirect */
	 for (server=1; global_wins_table[0][server].address.s_addr!=0; server++) {
		current = global_wins_table[partner][server].max_version;
		
		temp=0;
		
		for (other=1; other<partner_count; other++) {
			/* skip the partner itself */
			if (other==partner)
				continue;

			if (global_wins_table[other][server].max_version > temp)
				temp=global_wins_table[other][server].max_version;
		}
		
		if (current >= temp && current > global_wins_table[0][server].max_version) {
			/* 
			 * it has more records than every body else and more than us,
			 * ask it the difference between what we have and what it has
			 */
			fill_header(r, OPCODE_NON_NBT, get_server_assoc(q->header.assoc_ctx), MESSAGE_TYPE_REPLICATE);

			r->rep.msg_type=MESSAGE_REP_SEND_ENTRIES_REQUEST;
			r->rep.se_rq.wins_owner.address=global_wins_table[partner][server].address;
			
			r->rep.se_rq.wins_owner.max_version=global_wins_table[partner][server].max_version;
			r->rep.se_rq.wins_owner.min_version=global_wins_table[0][server].max_version;
			r->rep.se_rq.wins_owner.type=0;
			
			write_server_assoc_table(q->header.assoc_ctx, global_wins_table[0][partner].address, global_wins_table[partner][server].address);
			
			/*
			 * and we update our version for this server
			 * as we can't use the IDs returned in the send_entries function
			 * the max ID can be larger than the largest ID returned
			 */
			
			global_wins_table[0][server].max_version=global_wins_table[partner][server].max_version;

			return True;
		}
	}
	return False;
}
	
/****************************************************************************
receive the list of wins server we know.
****************************************************************************/
static void receive_version_number_map_table(GENERIC_PACKET *q, GENERIC_PACKET *r)
{
	fstring peer;
	struct in_addr addr;
	int i,j,k,l;
	int s_ctx=get_server_assoc(q->header.assoc_ctx);

	if (s_ctx==0) {
		DEBUG(5, ("receive_version_number_map_table: request for a partner not in our table\n"));
		stop_packet(q, r, STOP_REASON_USER_REASON);
		return;
	}

	fstrcpy(peer,get_peer_addr(q->fd));
	addr=*interpret_addr2(peer);

	get_our_last_id(&global_wins_table[0][0]);
	
	DEBUG(5,("receive_version_number_map_table: received a map of %d server from: %s\n", 
	          q->rep.avmt_rep.partner_count ,inet_ntoa(q->rep.avmt_rep.initiating_wins_server)));
	DEBUG(5,("real peer is: %s\n", peer));

	for (i=0; global_wins_table[0][i].address.s_addr!=addr.s_addr && i<partner_count;i++)
		;

	if (i==partner_count) {
		DEBUG(5,("receive_version_number_map_table: unknown partner: %s\n", peer));
		stop_packet(q, r, STOP_REASON_USER_REASON);
		return;
	}

	for (j=0; j<q->rep.avmt_rep.partner_count;j++) {
		/*
		 * search if we already have this entry or if it's a new one
		 * it can be a new one in case of propagation
		 */
		for (k=0; global_wins_table[0][k].address.s_addr!=0 && 
			  global_wins_table[0][k].address.s_addr!=q->rep.avmt_rep.wins_owner[j].address.s_addr; k++);

		global_wins_table[i][k].address.s_addr=q->rep.avmt_rep.wins_owner[j].address.s_addr;
		global_wins_table[i][k].max_version=q->rep.avmt_rep.wins_owner[j].max_version;
		global_wins_table[i][k].min_version=q->rep.avmt_rep.wins_owner[j].min_version;
		global_wins_table[i][k].type=q->rep.avmt_rep.wins_owner[j].type;
		
		/*
		 * in case it's a new one, rewrite the address for all the partner
		 * to reserve the slot.
		 */

		for(l=0; l<partner_count; l++)
			global_wins_table[l][k].address.s_addr=q->rep.avmt_rep.wins_owner[j].address.s_addr;
	}

	dump_global_table();

	/*
	 * if this server have newer records than what we have
	 * for several wins servers, we need to ask it.
	 * Alas a send entry request is only on one server.
	 * So in the send entry reply, we'll ask for the next server if required.
	 */

	if (check_partners_and_send_entries(q, r, i))
		return;

	/* it doesn't have more entries than us */
	stop_packet(q, r, STOP_REASON_USER_REASON);
}

/****************************************************************************
add an entry to the wins list we'll send.
****************************************************************************/
static BOOL add_record_to_winsname(WINS_NAME **wins_name, int *max_names, char *name, int type, int wins_flags, int id, struct in_addr *ip_list, int num_ips)
{
	WINS_NAME *temp_list;
	int i;
	int current=*max_names;

	temp_list=talloc_realloc(mem_ctx, *wins_name, (current+1)*sizeof(WINS_NAME));
	if (temp_list==NULL)
		return False;

	temp_list[current].name_len=0x11;
	
	safe_strcpy(temp_list[current].name, name, 15);

	temp_list[current].type=type;
	temp_list[current].empty=0;

	temp_list[current].name_flag=wins_flags;

	if ( (wins_flags&0x03) == 1 || (wins_flags&0x03)==2)
		temp_list[current].group_flag=0x01000000;
	else
		temp_list[current].group_flag=0x00000000;
	
	temp_list[current].id=id;
	
	temp_list[current].owner.s_addr=ip_list[0].s_addr;

	if (temp_list[current].name_flag & 2) {
		temp_list[current].num_ip=num_ips;
		temp_list[current].others=(struct in_addr *)talloc(mem_ctx, sizeof(struct in_addr)*num_ips);
		if (temp_list[current].others==NULL)
			return False;
	
		for (i=0; i<num_ips; i++)
			temp_list[current].others[i].s_addr=ip_list[i].s_addr;

	} else 
		temp_list[current].num_ip=1;

	temp_list[current].foo=0xffffffff;

	*wins_name=temp_list;
	
	return True;
}

/****************************************************************************
send the list of name we have.
****************************************************************************/
static void send_entry_request(GENERIC_PACKET *q, GENERIC_PACKET *r)
{
	int max_names=0;
	int i;
	time_t time_now = time(NULL);
	WINS_OWNER *wins_owner;
	TDB_CONTEXT *tdb;
	TDB_DATA kbuf, dbuf, newkey;
	int s_ctx=get_server_assoc(q->header.assoc_ctx);
	int num_interfaces = iface_count();

	if (s_ctx==0) {
		DEBUG(1, ("send_entry_request: request for a partner not in our table\n"));
		stop_packet(q, r, STOP_REASON_USER_REASON);
		return;
	}


	wins_owner=&q->rep.se_rq.wins_owner;
	r->rep.se_rp.wins_name=NULL;

	DEBUG(3,("send_entry_request: we have been asked to send the list of wins records\n"));
	DEBUGADD(3,("owned by: %s and between min: %d and max: %d\n", inet_ntoa(wins_owner->address),
		    (int)wins_owner->min_version, (int)wins_owner->max_version));

	/*
	 * if we are asked to send records owned by us
	 * we overwrite the wins ip with 0.0.0.0
	 * to make it easy in case of multihomed
	 */

	for (i=0; i<num_interfaces; i++)
		if (ip_equal(wins_owner->address, *iface_n_ip(i))) {
			wins_owner->address=*interpret_addr2("0.0.0.0");
			break;
		}


	tdb = tdb_open_log(lock_path(WINS_LIST), 0, TDB_DEFAULT, O_RDONLY, 0600);
	if (!tdb) {
		DEBUG(2,("send_entry_request: Can't open wins database file %s. Error was %s\n", WINS_LIST, strerror(errno) ));
		return;
	}

	for (kbuf = tdb_firstkey(tdb); 
	     kbuf.dptr; 
	     newkey = tdb_nextkey(tdb, kbuf), safe_free(kbuf.dptr), kbuf=newkey) {
		fstring name_type;
		pstring name, ip_str;
		char *p;
		int type = 0;
		int nb_flags;
		int ttl;
		unsigned int num_ips;
		int low, high;
		SMB_BIG_UINT version;
		struct in_addr wins_ip;
		struct in_addr *ip_list;
		int wins_flags;
		int len;

		if (strncmp(kbuf.dptr, ENTRY_PREFIX, strlen(ENTRY_PREFIX)) != 0)
			continue;
		
		
		dbuf = tdb_fetch(tdb, kbuf);
		if (!dbuf.dptr)
			continue;

		fstrcpy(name_type, kbuf.dptr+strlen(ENTRY_PREFIX));
		pstrcpy(name, name_type);

		if((p = strchr(name,'#')) != NULL) {
			*p = 0;
			sscanf(p+1,"%x",&type);
		}

		len = tdb_unpack(dbuf.dptr, dbuf.dsize, "dddfddd",
				&nb_flags,
				&high,
				&low,
				ip_str,
				&ttl, 
				&num_ips,
				&wins_flags);

		wins_ip=*interpret_addr2(ip_str);

 		/* Allocate the space for the ip_list. */
		if((ip_list = (struct in_addr *)talloc(mem_ctx,  num_ips * sizeof(struct in_addr))) == NULL) {
			SAFE_FREE(dbuf.dptr);
			DEBUG(0,("initialise_wins: talloc fail !\n"));
			return;
		}

		for (i = 0; i < num_ips; i++) {
			len += tdb_unpack(dbuf.dptr+len, dbuf.dsize-len, "f", ip_str);
			ip_list[i] = *interpret_addr2(ip_str);
		}

		SAFE_FREE(dbuf.dptr);

		/* add all entries that have 60 seconds or more to live */
		if ((ttl - 60) > time_now || ttl == PERMANENT_TTL) {
			if(ttl != PERMANENT_TTL)
				ttl -= time_now;
    
			DEBUG( 4, ("send_entry_request: add name: %s#%02x ttl = %d first IP %s flags = %2x\n",
			    name, type, ttl, inet_ntoa(ip_list[0]), nb_flags));

			/* add the record to the list to send */
			version=((SMB_BIG_UINT)high)<<32 | low;
			
			if (wins_owner->min_version<=version && wins_owner->max_version>=version &&
			    wins_owner->address.s_addr==wins_ip.s_addr) {
				if(!add_record_to_winsname(&r->rep.se_rp.wins_name, &max_names, name, type, wins_flags, version, ip_list, num_ips))
					return;
				max_names++;
			}

		} else {
			DEBUG(4, ("send_entry_request: not adding name (ttl problem) %s#%02x ttl = %d first IP %s flags = %2x\n",
				  name, type, ttl, inet_ntoa(ip_list[0]), nb_flags));
		}
	}
    
	tdb_close(tdb);

	DEBUG(4,("send_entry_request, sending %d records\n", max_names));
	fill_header(r, OPCODE_NON_NBT, s_ctx, MESSAGE_TYPE_REPLICATE);
	r->rep.msg_type=MESSAGE_REP_SEND_ENTRIES_REPLY; /* reply */
	r->rep.se_rp.max_names=max_names;
}


/****************************************************************************
.
****************************************************************************/
static void update_notify_request(GENERIC_PACKET *q, GENERIC_PACKET *r)
{
	int i,j,k,l;
	UPDATE_NOTIFY_REQUEST *u;
	int s_ctx=get_server_assoc(q->header.assoc_ctx);
	
	if (s_ctx==0) {
		DEBUG(4, ("update_notify_request: request for a partner not in our table\n"));
		stop_packet(q, r, STOP_REASON_USER_REASON);
		return;
	}

	u=&q->rep.un_rq;

	/* check if we already have the range of records */

	DEBUG(5,("update_notify_request: wins server: %s offered this list of %d records:\n",
		inet_ntoa(u->initiating_wins_server), u->partner_count));

	get_our_last_id(&global_wins_table[0][0]);

	for (i=0; i<partner_count; i++) {
		if (global_wins_table[0][i].address.s_addr==u->initiating_wins_server.s_addr) {
			DEBUG(5,("update_notify_request: found initiator at index %d\n", i));
			break;
		}
	}

	/*
	 * some explanation is required, before someone say it's crap.
	 *
	 * let's take an example, we have 2 wins partners, we already now
	 * that our max id is 10, partner 1 ID is 20 and partner 2 ID is 30
	 * the array looks like:
	 *
	 * 	0	1	2
	 * 0	10	20	30  
	 * 1
	 * 2
	 *
	 * we receive an update from partner 2 saying he has: 1:15, 2:40, 3:50
	 * we must enlarge the array to add partner 3, it will look like:
	 *
	 * 	0	1	2	3
	 * 0	10	20	30
	 * 1
	 * 2		15	40	50
	 *
	 * now we know, we should pull from partner 2, the records 30->40 of 2 and 0->50 of 3.
	 * once the pull will be over, our table will look like:
	 *
	 * 	0	1	2	3
	 * 0	10	20	40	50
	 * 1
	 * 2		15	40	50
	 *
	 *
	 */

	for (j=0; j<u->partner_count;j++) {
		/*
		 * search if we already have this entry or if it's a new one
		 * it can be a new one in case of propagation
		 */

		for (k=0; global_wins_table[0][k].address.s_addr!=0 && 
			  global_wins_table[0][k].address.s_addr!=u->wins_owner[j].address.s_addr; k++);

		global_wins_table[i][k].address.s_addr=u->wins_owner[j].address.s_addr;
		global_wins_table[i][k].max_version=u->wins_owner[j].max_version;
		global_wins_table[i][k].min_version=u->wins_owner[j].min_version;
		global_wins_table[i][k].type=u->wins_owner[j].type;
		
		/*
		 * in case it's a new one, rewrite the address for all the partner
		 * to reserve the slot.
		 */

		for(l=0; l<partner_count; l++)
			global_wins_table[l][k].address.s_addr=u->wins_owner[j].address.s_addr;
	}

	dump_global_table();

	stop_packet(q, r, STOP_REASON_USER_REASON);
}

/****************************************************************************
.
****************************************************************************/
static void send_entry_reply(GENERIC_PACKET *q, GENERIC_PACKET *r)
{
	int i,j,k;
	struct in_addr partner, server;
	pid_t pid;
	int s_ctx=get_server_assoc(q->header.assoc_ctx);
	WINS_RECORD record;
	
	if (s_ctx==0) {
		DEBUG(1, ("send_entry_reply: request for a partner not in our table\n"));
		stop_packet(q, r, STOP_REASON_USER_REASON);
		return;
	}

	DEBUG(5,("send_entry_reply:got %d new records\n", q->rep.se_rp.max_names));

	/* we got records from a wins partner but that can be from another wins server */
	/* hopefully we track that */

	/* and the only doc available from MS is wrong ! */

	get_server_assoc_table(q->header.assoc_ctx, &partner, &server);

	for (j=0; global_wins_table[0][j].address.s_addr!=0; j++) {
		if (global_wins_table[0][j].address.s_addr==server.s_addr) {
			DEBUG(5,("send_entry_reply: found server at index %d\n", j));
			break;
		}
	}

	pid = pidfile_pid("nmbd");
	if (pid == 0) {
		DEBUG(0,("send_entry_reply: Can't find pid for nmbd\n"));
		return;
	}

	for (k=0; k<q->rep.se_rp.max_names; k++) {
		DEBUG(5,("send_entry_reply: %s<%02x> %d\n", q->rep.se_rp.wins_name[k].name, q->rep.se_rp.wins_name[k].type,
		         (int)q->rep.se_rp.wins_name[k].id));

		safe_strcpy(record.name, q->rep.se_rp.wins_name[k].name, 16);
		record.type=q->rep.se_rp.wins_name[k].type;
		record.id=q->rep.se_rp.wins_name[k].id;
		record.wins_flags=q->rep.se_rp.wins_name[k].name_flag&0x00ff;
		record.num_ips=q->rep.se_rp.wins_name[k].num_ip;

		record.wins_ip.s_addr=server.s_addr;

		if (record.num_ips==1)
			record.ip[0]=q->rep.se_rp.wins_name[k].owner;
		else
			for (i=0; i<record.num_ips; i++)
				record.ip[i]=q->rep.se_rp.wins_name[k].others[i];

		record.nb_flags=0;

		if (record.wins_flags&WINS_NGROUP || record.wins_flags&WINS_SGROUP)
			record.nb_flags|=NB_GROUP;
		
		if (record.wins_flags&WINS_ACTIVE)
			record.nb_flags|=NB_ACTIVE;
		
		record.nb_flags|=record.wins_flags&WINS_HNODE;
		
		message_send_pid(pid, MSG_WINS_NEW_ENTRY, &record, sizeof(record), False);

	}

	dump_global_table();

	/*
	 * we got some entries, 
	 * ask the partner to send us the map table again
	 * to get the other servers entries.
	 *
	 * we're getting the map table 1 time more than really
	 * required. We could remove that call, but that
	 * would complexify the code. I prefer this trade-of. 
	 */
	fill_header(r, OPCODE_NON_NBT, s_ctx, MESSAGE_TYPE_REPLICATE);

	r->rep.msg_type=MESSAGE_REP_ADD_VERSION_REQUEST;
}

/****************************************************************************
decode the replication message and reply.
****************************************************************************/
static void replicate(GENERIC_PACKET *q, GENERIC_PACKET *r)
{
	switch (q->rep.msg_type) {
		case 0:
			/* add version number map table request */
			send_version_number_map_table(q, r);
			break;
		case 1:
			receive_version_number_map_table(q, r);
			break;
		case 2:
			/* send entry request */
			send_entry_request(q, r);
			break;
		case 3:
			/* send entry reply */
			send_entry_reply(q, r);
			break;
		case 4:
			/* update notification request */
			update_notify_request(q, r);
			break;
	}
}

/****************************************************************************
do a switch on the message type, and return the response size
****************************************************************************/
static BOOL switch_message(GENERIC_PACKET *q, GENERIC_PACKET *r)
{
	switch (q->header.mess_type) {
		case 0:
			/* Start association type */			
			start_assoc_process(q, r);
			return True;
			break;
		case 1:
			/* start association reply */
			start_assoc_reply(q, r);
			return True;
			break;
		case 2:
			/* stop association message */
			return False;
			break;
		case 3:
			/* replication message */
			replicate(q, r);
			return True;
			break;
	}

	return False;
}


/****************************************************************************
  construct a reply to the incoming packet
****************************************************************************/
void construct_reply(struct wins_packet_struct *p)
{
	GENERIC_PACKET r;
	struct BUFFER buffer;

	buffer.buffer=NULL;
	buffer.offset=0;
	buffer.length=0;

	DEBUG(5,("dump: received packet\n"));
	dump_generic_packet(p->packet);

	/* Verify if the request we got is from a listed partner */
	if (!check_partner(p->packet->header.assoc_ctx)) {
		fstring peer;
		struct in_addr addr;
		int i;
		fstrcpy(peer,get_peer_addr(p->fd));
		addr=*interpret_addr2(peer);

		for (i=1; i<partner_count; i++)
			if (ip_equal(addr, global_wins_table[0][i].address))
				break;

		if (i==partner_count) {
			DEBUG(1,("construct_reply: got a request from a non peer machine: %s\n", peer));
			stop_packet(p->packet, &r, STOP_REASON_AUTH_FAILED);
			p->stop_packet=True;
			encode_generic_packet(&buffer, &r);
			if (!send_smb(p->fd, buffer.buffer))
				exit_server("process_smb: send_smb failed.");
			return;
		}
	}

	if (switch_message(p->packet, &r)) {
		encode_generic_packet(&buffer, &r);
		DEBUG(5,("dump: sending packet\n"));
		dump_generic_packet(&r);

		if(buffer.offset > 0) {
			if (!send_smb(p->fd, buffer.buffer))
				exit_server("process_smb: send_smb failed.");
		}
	}

	/* if we got a stop assoc or if we send a stop assoc, close the fd after */
	if (p->packet->header.mess_type==MESSAGE_TYPE_STOP_ASSOC || 
	    r.header.mess_type==MESSAGE_TYPE_STOP_ASSOC) {
	    	remove_partner(p->packet->header.assoc_ctx);
		p->stop_packet=True;
	}
}

/****************************************************************************
  contact periodically our wins partner to do a pull replication
****************************************************************************/
void run_pull_replication(time_t t)
{
	/* we pull every 30 minutes to query about new records*/
	int i, s;
	struct BUFFER buffer;
	GENERIC_PACKET p;

	buffer.buffer=NULL;
	buffer.offset=0;
	buffer.length=0;

	for (i=1; i<partner_count; i++) {
		if (global_wins_table[0][i].last_pull < t) {
			global_wins_table[0][i].last_pull=t+30*60; /* next in 30 minutes */
			
			/* contact the wins server */
			p.header.mess_type=MESSAGE_TYPE_START_ASSOC_REQUEST;
			p.header.opcode=OPCODE_NON_NBT;
			p.header.assoc_ctx=0;
			p.sa_rq.assoc_ctx=(int)t;
			p.sa_rq.min_ver=1;
			p.sa_rq.maj_ver=1;
			
			DEBUG(3,("run_pull_replication: contacting wins server %s.\n", inet_ntoa(global_wins_table[0][i].address)));
			encode_generic_packet(&buffer, &p);
			dump_generic_packet(&p);

			/* send the packet to the server and add the descriptor to receive answers */
			s=open_socket_out(SOCK_STREAM, &global_wins_table[0][i].address, 42, LONG_CONNECT_TIMEOUT);
			if (s==-1) {
				DEBUG(0,("run_pull_replication: can't contact wins server %s.\n", inet_ntoa(global_wins_table[0][i].address)));
				return;
			}
			
			if(buffer.offset > 0) {
				if (!send_smb(s, buffer.buffer))
					exit_server("run_pull_replication: send_smb failed.");
			}
			
			add_fd_to_sock_array(s);
			FD_SET(s, listen_set);

			/* add ourself as a client */
			add_partner((int)t, 0, True, False);
		}
	}
}

/****************************************************************************
  contact periodically our wins partner to do a push replication
****************************************************************************/
void run_push_replication(time_t t)
{
	/* we push every 30 minutes or 25 new entries */
	int i, s;
	struct BUFFER buffer;
	GENERIC_PACKET p;

	buffer.buffer=NULL;
	buffer.offset=0;
	buffer.length=0;

	for (i=1; i<partner_count; i++) {
		if (global_wins_table[0][i].last_pull < t) {
			global_wins_table[0][i].last_pull=t+30*60; /* next in 30 minutes */
			
			/* contact the wins server */
			p.header.mess_type=MESSAGE_TYPE_START_ASSOC_REQUEST;
			p.header.opcode=OPCODE_NON_NBT;
			p.header.assoc_ctx=0;
			p.sa_rq.assoc_ctx=(int)t;
			p.sa_rq.min_ver=1;
			p.sa_rq.maj_ver=1;
			
			DEBUG(3,("run_push_replication: contacting wins server %s.\n", inet_ntoa(global_wins_table[0][i].address)));
			encode_generic_packet(&buffer, &p);
			dump_generic_packet(&p);

			/* send the packet to the server and add the descriptor to receive answers */
			s=open_socket_out(SOCK_STREAM, &global_wins_table[0][i].address, 42, LONG_CONNECT_TIMEOUT);
			if (s==-1) {
				DEBUG(0,("run_push_replication: can't contact wins server %s.\n", inet_ntoa(global_wins_table[0][i].address)));
				return;
			}
			
			if(buffer.offset > 0) {
				if (!send_smb(s, buffer.buffer))
					exit_server("run_push_replication: send_smb failed.");
			}
			
			add_fd_to_sock_array(s);
			FD_SET(s, listen_set);

			/* add ourself as a client */
			add_partner((int)t, 0, False, True);
		}
	}
}

