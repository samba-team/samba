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

#include "includes.h"
#include "wins_repl.h"

extern TALLOC_CTX *mem_ctx;

/****************************************************************************
grow the send buffer if necessary
****************************************************************************/
BOOL grow_buffer(struct BUFFER *buffer, int more)
{
	char *temp;

	DEBUG(10,("grow_buffer: size is: %d offet is:%d growing by %d\n", buffer->length, buffer->offset, more));
	
	/* grow by at least 256 bytes */
	if (more<256)
		more=256;

	if (buffer->offset+more >= buffer->length) {
		temp=(char *)talloc_realloc(mem_ctx, buffer->buffer, sizeof(char)* (buffer->length+more) );
		if (temp==NULL) {
			DEBUG(0,("grow_buffer: can't grow buffer\n"));
			return False;
		}
		buffer->length+=more;
		buffer->buffer=temp;
	}

	return True;
}

/****************************************************************************
check if the buffer has that much data
****************************************************************************/
static BOOL check_buffer(struct BUFFER *buffer, int more)
{
	DEBUG(10,("check_buffer: size is: %d offet is:%d growing by %d\n", buffer->length, buffer->offset, more));
	
	if (buffer->offset+more > buffer->length) {
		DEBUG(10,("check_buffer: buffer smaller than requested, size is: %d needed: %d\n", buffer->length, buffer->offset+more));
		return False;
	}

	return True;
}

/****************************************************************************
decode a WINS_OWNER struct
****************************************************************************/
static void decode_wins_owner(struct BUFFER *inbuf, WINS_OWNER *wins_owner)
{
	if(!check_buffer(inbuf, 24))
		return;

	wins_owner->address.s_addr=IVAL(inbuf->buffer, inbuf->offset);
	wins_owner->max_version=((SMB_BIG_UINT)RIVAL(inbuf->buffer, inbuf->offset+4))<<32;
	wins_owner->max_version|=RIVAL(inbuf->buffer, inbuf->offset+8);
	wins_owner->min_version=((SMB_BIG_UINT)RIVAL(inbuf->buffer, inbuf->offset+12))<<32;
	wins_owner->min_version|=RIVAL(inbuf->buffer, inbuf->offset+16);
	wins_owner->type=RIVAL(inbuf->buffer, inbuf->offset+20);
	inbuf->offset+=24;

}

/****************************************************************************
decode a WINS_NAME struct
****************************************************************************/
static void decode_wins_name(struct BUFFER *outbuf, WINS_NAME *wins_name)
{	
	char *p;
	int i;

	if(!check_buffer(outbuf, 40))
		return;

	wins_name->name_len=RIVAL(outbuf->buffer, outbuf->offset);
	outbuf->offset+=4;
	memcpy(wins_name->name,outbuf->buffer+outbuf->offset, 15);
	wins_name->name[15]='\0';
	if((p = strchr(wins_name->name,' ')) != NULL)
		*p = 0;

	outbuf->offset+=15;

	wins_name->type=(int)outbuf->buffer[outbuf->offset++];
	
	/*
	 * fix to bug in WINS replication,
	 * present in all versions including W2K SP2 !
	 */
	if (wins_name->name[0]==0x1B) {
		wins_name->name[0]=(char)wins_name->type;
		wins_name->type=0x1B;
	}
	
	wins_name->empty=RIVAL(outbuf->buffer, outbuf->offset);
	outbuf->offset+=4;
	
	wins_name->name_flag=RIVAL(outbuf->buffer, outbuf->offset);
	outbuf->offset+=4;
	wins_name->group_flag=RIVAL(outbuf->buffer, outbuf->offset);
	outbuf->offset+=4;
	wins_name->id=((SMB_BIG_UINT)RIVAL(outbuf->buffer, outbuf->offset))<<32;
	outbuf->offset+=4;
	wins_name->id|=RIVAL(outbuf->buffer, outbuf->offset);
	outbuf->offset+=4;
	
	/* special groups have multiple address */
	if (wins_name->name_flag & 2) {
		if(!check_buffer(outbuf, 4))
			return;
		wins_name->num_ip=IVAL(outbuf->buffer, outbuf->offset);
		outbuf->offset+=4;
	}
	else
		wins_name->num_ip=1;

	if(!check_buffer(outbuf, 4))
		return;
	wins_name->owner.s_addr=IVAL(outbuf->buffer, outbuf->offset);
	outbuf->offset+=4;

	if (wins_name->name_flag & 2) {
		wins_name->others=(struct in_addr *)talloc(mem_ctx, sizeof(struct in_addr)*wins_name->num_ip);
		if (wins_name->others==NULL)
			return;

		if(!check_buffer(outbuf, 4*wins_name->num_ip))
			return;
		for (i=0; i<wins_name->num_ip; i++) {
			wins_name->others[i].s_addr=IVAL(outbuf->buffer, outbuf->offset);
			outbuf->offset+=4;
		}
	}

	if(!check_buffer(outbuf, 4))
		return;
	wins_name->foo=RIVAL(outbuf->buffer, outbuf->offset);
	outbuf->offset+=4;

}

/****************************************************************************
decode a update notification request
****************************************************************************/
static void decode_update_notify_request(struct BUFFER *inbuf, UPDATE_NOTIFY_REQUEST *un_rq)
{
	int i;

	if(!check_buffer(inbuf, 4))
		return;
	un_rq->partner_count=RIVAL(inbuf->buffer, inbuf->offset);
	inbuf->offset+=4;

	un_rq->wins_owner=(WINS_OWNER *)talloc(mem_ctx, un_rq->partner_count*sizeof(WINS_OWNER));
	if (un_rq->wins_owner==NULL)
		return;

	for (i=0; i<un_rq->partner_count; i++)
		decode_wins_owner(inbuf, &un_rq->wins_owner[i]);

	if(!check_buffer(inbuf, 4))
		return;
	un_rq->initiating_wins_server.s_addr=IVAL(inbuf->buffer, inbuf->offset);
	inbuf->offset+=4;
}

/****************************************************************************
decode a send entries request
****************************************************************************/
static void decode_send_entries_request(struct BUFFER *inbuf, SEND_ENTRIES_REQUEST *se_rq)
{
	decode_wins_owner(inbuf, &se_rq->wins_owner);
}

/****************************************************************************
decode a send entries reply
****************************************************************************/
static void decode_send_entries_reply(struct BUFFER *inbuf, SEND_ENTRIES_REPLY *se_rp)
{
	int i;

	if(!check_buffer(inbuf, 4))
		return;
	se_rp->max_names = RIVAL(inbuf->buffer, inbuf->offset);
	inbuf->offset+=4;

	se_rp->wins_name=(WINS_NAME *)talloc(mem_ctx, se_rp->max_names*sizeof(WINS_NAME));
	if (se_rp->wins_name==NULL)
		return;

	for (i=0; i<se_rp->max_names; i++)
		decode_wins_name(inbuf, &se_rp->wins_name[i]);
}

/****************************************************************************
decode a add version number map table reply
****************************************************************************/
static void decode_add_version_number_map_table_reply(struct BUFFER *inbuf, AVMT_REP *avmt_rep)
{
	int i;

	if(!check_buffer(inbuf, 4))
		return;

	avmt_rep->partner_count=RIVAL(inbuf->buffer, inbuf->offset);
	inbuf->offset+=4;

	avmt_rep->wins_owner=(WINS_OWNER *)talloc(mem_ctx, avmt_rep->partner_count*sizeof(WINS_OWNER));
	if (avmt_rep->wins_owner==NULL)
		return;

	for (i=0; i<avmt_rep->partner_count; i++)
		decode_wins_owner(inbuf, &avmt_rep->wins_owner[i]);

	if(!check_buffer(inbuf, 4))
		return;
	avmt_rep->initiating_wins_server.s_addr=IVAL(inbuf->buffer, inbuf->offset);
	inbuf->offset+=4;
}

/****************************************************************************
decode a replicate packet and fill a structure
****************************************************************************/
static void decode_replicate(struct BUFFER *inbuf, REPLICATE *rep)
{
	if(!check_buffer(inbuf, 4))
		return;

	rep->msg_type = RIVAL(inbuf->buffer, inbuf->offset);

	inbuf->offset+=4;

	switch (rep->msg_type) {
		case 0:
			break;
		case 1:
			/* add version number map table reply */
			decode_add_version_number_map_table_reply(inbuf, &rep->avmt_rep);
			break;
		case 2:
			/* send entry request */
			decode_send_entries_request(inbuf, &rep->se_rq);
			break;
		case 3:
			/* send entry request */
			decode_send_entries_reply(inbuf, &rep->se_rp);
			break;
		case 4:
			/* update notification request */
			decode_update_notify_request(inbuf, &rep->un_rq);
			break;
		default:
			DEBUG(0,("decode_replicate: unknown message type:%d\n", rep->msg_type));
			break;
	}
}

/****************************************************************************
read the generic header and fill the struct.
****************************************************************************/
static void read_generic_header(struct BUFFER *inbuf, generic_header *q)
{
	if(!check_buffer(inbuf, 16))
		return;

	q->data_size = RIVAL(inbuf->buffer, inbuf->offset+0);
	q->opcode    = RIVAL(inbuf->buffer, inbuf->offset+4);
	q->assoc_ctx = RIVAL(inbuf->buffer, inbuf->offset+8);
	q->mess_type = RIVAL(inbuf->buffer, inbuf->offset+12);
}

/*******************************************************************
decode a start association request
********************************************************************/
static void decode_start_assoc_request(struct BUFFER *inbuf, START_ASSOC_REQUEST *q)
{
	if(!check_buffer(inbuf, 8))
		return;

	q->assoc_ctx = RIVAL(inbuf->buffer, inbuf->offset+0);
	q->min_ver = RSVAL(inbuf->buffer, inbuf->offset+4);
	q->maj_ver = RSVAL(inbuf->buffer, inbuf->offset+6);
}

/*******************************************************************
decode a start association reply
********************************************************************/
static void decode_start_assoc_reply(struct BUFFER *inbuf, START_ASSOC_REPLY *r)
{
	if(!check_buffer(inbuf, 8))
		return;

	r->assoc_ctx=RIVAL(inbuf->buffer, inbuf->offset+0);
	r->min_ver = RSVAL(inbuf->buffer, inbuf->offset+4);
	r->maj_ver = RSVAL(inbuf->buffer, inbuf->offset+6);
}

/*******************************************************************
decode a start association reply
********************************************************************/
static void decode_stop_assoc(struct BUFFER *inbuf, STOP_ASSOC *r)
{
	if(!check_buffer(inbuf, 4))
		return;

	r->reason=RIVAL(inbuf->buffer, inbuf->offset);
}

/****************************************************************************
decode a packet and fill a generic structure
****************************************************************************/
void decode_generic_packet(struct BUFFER *inbuf, GENERIC_PACKET *q)
{
	read_generic_header(inbuf, &q->header);

	inbuf->offset+=16;

	switch (q->header.mess_type) {
		case 0:
			decode_start_assoc_request(inbuf, &q->sa_rq);
			break;
		case 1:
			decode_start_assoc_reply(inbuf, &q->sa_rp);
			break;
		case 2:
			decode_stop_assoc(inbuf, &q->so);
			break;
		case 3:
			decode_replicate(inbuf, &q->rep);
			break;
		default:
			DEBUG(0,("decode_generic_packet: unknown message type:%d\n", q->header.mess_type));
			break;
	}
}

/****************************************************************************
encode a WINS_OWNER struct
****************************************************************************/
static void encode_wins_owner(struct BUFFER *outbuf, WINS_OWNER *wins_owner)
{
	if (!grow_buffer(outbuf, 24))
		return;

	SIVAL(outbuf->buffer, outbuf->offset, wins_owner->address.s_addr);
	outbuf->offset+=4;
	RSIVAL(outbuf->buffer, outbuf->offset, (int)(wins_owner->max_version>>32));
	outbuf->offset+=4;
	RSIVAL(outbuf->buffer, outbuf->offset, (int)(wins_owner->max_version&0xffffffff));
	outbuf->offset+=4;
	RSIVAL(outbuf->buffer, outbuf->offset, wins_owner->min_version>>32);
	outbuf->offset+=4;
	RSIVAL(outbuf->buffer, outbuf->offset, wins_owner->min_version&0xffffffff);
	outbuf->offset+=4;
	RSIVAL(outbuf->buffer, outbuf->offset, wins_owner->type);
	outbuf->offset+=4;
	
}

/****************************************************************************
encode a WINS_NAME struct
****************************************************************************/
static void encode_wins_name(struct BUFFER *outbuf, WINS_NAME *wins_name)
{	
	int i;

	if (!grow_buffer(outbuf, 48+(4*wins_name->num_ip)))
		return;

	RSIVAL(outbuf->buffer, outbuf->offset, wins_name->name_len);
	outbuf->offset+=4;
	
	memset(outbuf->buffer+outbuf->offset, ' ', 15);

	/* to prevent copying the leading \0 */
	memcpy(outbuf->buffer+outbuf->offset, wins_name->name, strlen(wins_name->name));
	outbuf->offset+=15;		

	outbuf->buffer[outbuf->offset++]=(char)wins_name->type;

	RSIVAL(outbuf->buffer, outbuf->offset, wins_name->empty);
	outbuf->offset+=4;

	RSIVAL(outbuf->buffer, outbuf->offset, wins_name->name_flag);
	outbuf->offset+=4;
	RSIVAL(outbuf->buffer, outbuf->offset, wins_name->group_flag);
	outbuf->offset+=4;
	RSIVAL(outbuf->buffer, outbuf->offset, wins_name->id>>32);
	outbuf->offset+=4;
	RSIVAL(outbuf->buffer, outbuf->offset, wins_name->id);
	outbuf->offset+=4;

	if (wins_name->name_flag & 2) {
		SIVAL(outbuf->buffer, outbuf->offset, wins_name->num_ip);
		outbuf->offset+=4;
	}	

	SIVAL(outbuf->buffer, outbuf->offset, wins_name->owner.s_addr);
	outbuf->offset+=4;

	if (wins_name->name_flag & 2) {
		for (i=0;i<wins_name->num_ip;i++) {
			SIVAL(outbuf->buffer, outbuf->offset, wins_name->others[i].s_addr);
			outbuf->offset+=4;
		}
	}	

	RSIVAL(outbuf->buffer, outbuf->offset, wins_name->foo);
	outbuf->offset+=4;
}

/****************************************************************************
encode a update notification request
****************************************************************************/
static void encode_update_notify_request(struct BUFFER *outbuf, UPDATE_NOTIFY_REQUEST *un_rq)
{
	int i;

	if (!grow_buffer(outbuf, 8))
		return;
		
	RSIVAL(outbuf->buffer, outbuf->offset, un_rq->partner_count);
	outbuf->offset+=4;

	for (i=0; i<un_rq->partner_count; i++)
		encode_wins_owner(outbuf,  &un_rq->wins_owner[i]);

	SIVAL(outbuf->buffer, outbuf->offset, un_rq->initiating_wins_server.s_addr);
	outbuf->offset+=4;
	
}

/****************************************************************************
decode a send entries request
****************************************************************************/
static void encode_send_entries_request(struct BUFFER *outbuf, SEND_ENTRIES_REQUEST *se_rq)
{
	encode_wins_owner(outbuf, &se_rq->wins_owner);
}

/****************************************************************************
decode a send entries reply
****************************************************************************/
static void encode_send_entries_reply(struct BUFFER *outbuf, SEND_ENTRIES_REPLY *se_rp)
{
	int i;

	if (!grow_buffer(outbuf, 4))
		return;
		
	RSIVAL(outbuf->buffer, outbuf->offset, se_rp->max_names);
	outbuf->offset+=4;

	for (i=0; i<se_rp->max_names; i++)
		encode_wins_name(outbuf, &se_rp->wins_name[i]);

}

/****************************************************************************
encode a add version number map table reply
****************************************************************************/
static void encode_add_version_number_map_table_reply(struct BUFFER *outbuf, AVMT_REP *avmt_rep)
{
	int i;

	if (!grow_buffer(outbuf, 8))
		return;

	RSIVAL(outbuf->buffer, outbuf->offset, avmt_rep->partner_count);
	outbuf->offset+=4;
	
	for (i=0; i<avmt_rep->partner_count; i++)
		encode_wins_owner(outbuf, &avmt_rep->wins_owner[i]);

	SIVAL(outbuf->buffer, outbuf->offset, avmt_rep->initiating_wins_server.s_addr);
	outbuf->offset+=4;
	
}

/****************************************************************************
decode a replicate packet and fill a structure
****************************************************************************/
static void encode_replicate(struct BUFFER *outbuf, REPLICATE *rep)
{
	if (!grow_buffer(outbuf, 4))
		return;

	RSIVAL(outbuf->buffer, outbuf->offset, rep->msg_type);
	outbuf->offset+=4;

	switch (rep->msg_type) {
		case 0:
			break;
		case 1:
			/* add version number map table reply */
			encode_add_version_number_map_table_reply(outbuf, &rep->avmt_rep);
			break;
		case 2:
			/* send entry request */
			encode_send_entries_request(outbuf, &rep->se_rq);
			break;
		case 3:
			/* send entry request */
			encode_send_entries_reply(outbuf, &rep->se_rp);
			break;
		case 4:
			/* update notification request */
			encode_update_notify_request(outbuf, &rep->un_rq);
			break;
		default:
			DEBUG(0,("encode_replicate: unknown message type:%d\n", rep->msg_type));
			break;
	}
}

/****************************************************************************
write the generic header.
****************************************************************************/
static void write_generic_header(struct BUFFER *outbuf, generic_header *r)
{
	RSIVAL(outbuf->buffer, 0, r->data_size);
	RSIVAL(outbuf->buffer, 4, r->opcode);
	RSIVAL(outbuf->buffer, 8, r->assoc_ctx);
	RSIVAL(outbuf->buffer,12, r->mess_type);
}

/*******************************************************************
decode a start association request
********************************************************************/
static void encode_start_assoc_request(struct BUFFER *outbuf, START_ASSOC_REQUEST *q)
{
	if (!grow_buffer(outbuf, 45))
		return;

	RSIVAL(outbuf->buffer, outbuf->offset, q->assoc_ctx);
	RSSVAL(outbuf->buffer, outbuf->offset+4, q->min_ver);
	RSSVAL(outbuf->buffer, outbuf->offset+6, q->maj_ver);
	
	outbuf->offset=45;
}

/*******************************************************************
decode a start association reply
********************************************************************/
static void encode_start_assoc_reply(struct BUFFER *outbuf, START_ASSOC_REPLY *r)
{
	if (!grow_buffer(outbuf, 45))
		return;

	RSIVAL(outbuf->buffer, outbuf->offset, r->assoc_ctx);
	RSSVAL(outbuf->buffer, outbuf->offset+4, r->min_ver);
	RSSVAL(outbuf->buffer, outbuf->offset+6, r->maj_ver);

	outbuf->offset=45;
}

/*******************************************************************
decode a start association reply
********************************************************************/
static void encode_stop_assoc(struct BUFFER *outbuf, STOP_ASSOC *r)
{
	if (!grow_buffer(outbuf, 44))
		return;

	RSIVAL(outbuf->buffer, outbuf->offset, r->reason);
	
	outbuf->offset=44;
}

/****************************************************************************
write the generic header size.
****************************************************************************/
static void write_generic_header_size(generic_header *r, int size)
{
	/* the buffer size is the total size minus the size field */
	r->data_size=size-4;
}

/****************************************************************************
encode a packet and read a generic structure
****************************************************************************/
void encode_generic_packet(struct BUFFER *outbuf, GENERIC_PACKET *q)
{
	if (!grow_buffer(outbuf, 16))
		return;

	outbuf->offset=16;

	switch (q->header.mess_type) {
		case 0:
			encode_start_assoc_request(outbuf, &q->sa_rq);
			break;
		case 1:
			encode_start_assoc_reply(outbuf, &q->sa_rp);
			break;
		case 2:
			encode_stop_assoc(outbuf, &q->so);
			break;
		case 3:
			encode_replicate(outbuf, &q->rep);
			break;
		default:
			DEBUG(0,("encode_generic_packet: unknown message type:%d\n", q->header.mess_type));
			break;
	}
	
	write_generic_header_size(&q->header, outbuf->offset);
	write_generic_header(outbuf, &q->header);
}


/****************************************************************************
dump a WINS_OWNER structure
****************************************************************************/
static void dump_wins_owner(WINS_OWNER *wins_owner)
{
	DEBUGADD(10,("\t\t\t\taddress         : %s\n", inet_ntoa(wins_owner->address)));
	DEBUGADD(10,("\t\t\t\tmax version: %d\n", (int)wins_owner->max_version));
	DEBUGADD(10,("\t\t\t\tmin version: %d\n", (int)wins_owner->min_version));
	DEBUGADD(10,("\t\t\t\ttype            : %d\n", wins_owner->type));
}

/****************************************************************************
dump a WINS_NAME structure
****************************************************************************/
static void dump_wins_name(WINS_NAME *wins_name)
{
	fstring name;
	int i;

	strncpy(name, wins_name->name, 15);

	DEBUGADD(10,("name: %d, %s<%02x> %x,%x, %d %s %d ", wins_name->name_len, name, wins_name->type,
		    wins_name->name_flag, wins_name->group_flag, (int)wins_name->id,
		    inet_ntoa(wins_name->owner), wins_name->num_ip));

	if (wins_name->num_ip!=1)
		for (i=0; i<wins_name->num_ip; i++)
			DEBUGADD(10,("%s ", inet_ntoa(wins_name->others[i])));	

	DEBUGADD(10,("\n"));
}

/****************************************************************************
dump a replicate structure
****************************************************************************/
static void dump_replicate(REPLICATE *rep)
{
	int i;

	DEBUGADD(5,("\t\tmsg_type: %d ", rep->msg_type));

	switch (rep->msg_type) {
		case 0:
			DEBUGADD(5,("(Add Version Map Table Request)\n"));
			break;
		case 1:
			DEBUGADD(5,("(Add Version Map Table Reply)\n"));
			DEBUGADD(5,("\t\t\tpartner_count         : %d\n", rep->avmt_rep.partner_count));
			for (i=0; i<rep->avmt_rep.partner_count; i++)
				dump_wins_owner(&rep->avmt_rep.wins_owner[i]);
			DEBUGADD(5,("\t\t\tinitiating_wins_server: %s\n", inet_ntoa(rep->avmt_rep.initiating_wins_server)));
			break;
		case 2:
			DEBUGADD(5,("(Send Entries Request)\n"));
			dump_wins_owner(&rep->se_rq.wins_owner);
			break;
		case 3:
			DEBUGADD(5,("(Send Entries Reply)\n"));
			DEBUGADD(5,("\t\t\tmax_names         : %d\n", rep->se_rp.max_names));
			for (i=0; i<rep->se_rp.max_names; i++)
				dump_wins_name(&rep->se_rp.wins_name[i]);
			break;
		case 4:
			DEBUGADD(5,("(Update Notify Request)\n"));
			DEBUGADD(5,("\t\t\tpartner_count         : %d\n", rep->un_rq.partner_count));
			for (i=0; i<rep->un_rq.partner_count; i++)
				dump_wins_owner(&rep->un_rq.wins_owner[i]);
			DEBUGADD(5,("\t\t\tinitiating_wins_server: %s\n", inet_ntoa(rep->un_rq.initiating_wins_server)));
			break;
		default:
			DEBUG(5,("\n"));
			break;
	}
}

/****************************************************************************
dump a generic structure
****************************************************************************/
void dump_generic_packet(GENERIC_PACKET *q)
{
	DEBUG(5,("dump_generic_packet:\n"));
	DEBUGADD(5,("\tdata_size: %08x\n", q->header.data_size));
	DEBUGADD(5,("\topcode   : %08x\n", q->header.opcode));
	DEBUGADD(5,("\tassoc_ctx: %08x\n", q->header.assoc_ctx));
	DEBUGADD(5,("\tmess_type: %08x ", q->header.mess_type));

	switch (q->header.mess_type) {
		case 0:
			DEBUGADD(5,("(Start Association Request)\n"));
			DEBUGADD(5,("\t\tassoc_ctx: %08x\n", q->sa_rq.assoc_ctx));
			DEBUGADD(5,("\t\tmin_ver  : %04x\n", q->sa_rq.min_ver));
			DEBUGADD(5,("\t\tmaj_ver  : %04x\n", q->sa_rq.maj_ver));
			break;
		case 1:
			DEBUGADD(5,("(Start Association Reply)\n"));
			DEBUGADD(5,("\t\tassoc_ctx: %08x\n", q->sa_rp.assoc_ctx));
			DEBUGADD(5,("\t\tmin_ver  : %04x\n", q->sa_rp.min_ver));
			DEBUGADD(5,("\t\tmaj_ver  : %04x\n", q->sa_rp.maj_ver));
			break;
		case 2:
			DEBUGADD(5,("(Stop Association)\n"));
			DEBUGADD(5,("\t\treason: %08x\n", q->so.reason));
			break;
		case 3:
			DEBUGADD(5,("(Replication Message)\n"));
			dump_replicate(&q->rep);
			break;
		default:
			DEBUG(5,("\n"));
			break;
	}

}

/****************************************************************************
generate a stop packet
****************************************************************************/
void stop_packet(GENERIC_PACKET *q, GENERIC_PACKET *r, int reason)
{
	r->header.opcode=OPCODE_NON_NBT;
	r->header.assoc_ctx=get_server_assoc(q->header.assoc_ctx);
	r->header.mess_type=MESSAGE_TYPE_STOP_ASSOC;
	r->so.reason=reason;
	
}


