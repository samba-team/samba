/* 
   Unix SMB/CIFS implementation.
   SMB Signing Code
   Copyright (C) Jeremy Allison 2003.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
   
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

/* Lookup a packet's MID (multiplex id) and figure out it's sequence number */
struct outstanding_packet_lookup {
	uint16 mid;
	uint32 reply_seq_num;
	struct outstanding_packet_lookup *prev, *next;
};

/* Store the data for an ongoing trans/trans2/nttrans operation. */
struct trans_info_context {
	uint16 mid;
	uint32 send_seq_num;
	uint32 reply_seq_num;
};

struct smb_basic_signing_context {
	DATA_BLOB mac_key;
	uint32 send_seq_num;
	struct trans_info_context *trans_info;
	struct outstanding_packet_lookup *outstanding_packet_list;
};

static void store_sequence_for_reply(struct outstanding_packet_lookup **list, 
				     uint16 mid, uint32 reply_seq_num)
{
	struct outstanding_packet_lookup *t;

	t = smb_xmalloc(sizeof(*t));
	ZERO_STRUCTP(t);

	t->mid = mid;
	t->reply_seq_num = reply_seq_num;

	/*
	 * Add to the *start* of the list not the end of the list.
	 * This ensures that the *last* send sequence with this mid
	 * is returned by preference.
	 * This can happen if the mid wraps and one of the early
	 * mid numbers didn't get a reply and is still lurking on
	 * the list. JRA. Found by Fran Fabrizio <fran@cis.uab.edu>.
	 */

	DLIST_ADD(*list, t);
	DEBUG(10,("store_sequence_for_reply: stored seq = %u mid = %u\n",
			(unsigned int)reply_seq_num, (unsigned int)mid ));
}

static BOOL get_sequence_for_reply(struct outstanding_packet_lookup **list,
				   uint16 mid, uint32 *reply_seq_num)
{
	struct outstanding_packet_lookup *t;

	for (t = *list; t; t = t->next) {
		if (t->mid == mid) {
			*reply_seq_num = t->reply_seq_num;
			DEBUG(10,("get_sequence_for_reply: found seq = %u mid = %u\n",
				(unsigned int)t->reply_seq_num, (unsigned int)t->mid ));
			DLIST_REMOVE(*list, t);
			SAFE_FREE(t);
			return True;
		}
	}
	return False;
}

/***********************************************************
 SMB signing - Common code before we set a new signing implementation
************************************************************/

static BOOL cli_set_smb_signing_common(struct cli_state *cli) 
{
	if (!cli->sign_info.negotiated_smb_signing 
	    && !cli->sign_info.mandatory_signing) {
		return False;
	}

	if (cli->sign_info.doing_signing) {
		return False;
	}
	
	if (cli->sign_info.free_signing_context)
		cli->sign_info.free_signing_context(&cli->sign_info);

	/* These calls are INCOMPATIBLE with SMB signing */
	cli->readbraw_supported = False;
	cli->writebraw_supported = False;
	
	return True;
}

/***********************************************************
 SMB signing - Common code for 'real' implementations
************************************************************/

static BOOL set_smb_signing_real_common(struct smb_sign_info *si)
{
	if (si->mandatory_signing) {
		DEBUG(5, ("Mandatory SMB signing enabled!\n"));
	}

	si->doing_signing = True;
	DEBUG(5, ("SMB signing enabled!\n"));

	return True;
}

static void mark_packet_signed(char *outbuf)
{
	uint16 flags2;
	flags2 = SVAL(outbuf,smb_flg2);
	flags2 |= FLAGS2_SMB_SECURITY_SIGNATURES;
	SSVAL(outbuf,smb_flg2, flags2);
}

/***********************************************************
 SMB signing - NULL implementation - calculate a MAC to send.
************************************************************/

static void null_sign_outgoing_message(char *outbuf, struct smb_sign_info *si)
{
	/* we can't zero out the sig, as we might be trying to send a
	   session request - which is NBT-level, not SMB level and doesn't
	   have the field */
	return;
}

/***********************************************************
 SMB signing - NULL implementation - check a MAC sent by server.
************************************************************/

static BOOL null_check_incoming_message(char *inbuf, struct smb_sign_info *si, BOOL must_be_ok)
{
	return True;
}

/***********************************************************
 SMB signing - NULL implementation - free signing context
************************************************************/

static void null_free_signing_context(struct smb_sign_info *si)
{
	return;
}

/**
 SMB signing - NULL implementation - setup the MAC key.

 @note Used as an initialisation only - it will not correctly
       shut down a real signing mechanism
*/

static BOOL null_set_signing(struct smb_sign_info *si)
{
	si->signing_context = NULL;
	
	si->sign_outgoing_message = null_sign_outgoing_message;
	si->check_incoming_message = null_check_incoming_message;
	si->free_signing_context = null_free_signing_context;

	return True;
}

/**
 * Free the signing context
 */
 
static void free_signing_context(struct smb_sign_info *si)
{
	if (si->free_signing_context) {
		si->free_signing_context(si);
		si->signing_context = NULL;
	}

	null_set_signing(si);
}


static BOOL signing_good(char *inbuf, struct smb_sign_info *si, BOOL good, uint32 seq, BOOL must_be_ok) 
{
	if (good) {

		if (!si->doing_signing) {
			si->doing_signing = True;
		}
		
		if (!si->seen_valid) {
			si->seen_valid = True;
		}

	} else {
		if (!si->mandatory_signing && !si->seen_valid) {

			if (!must_be_ok) {
				return True;
			}
			/* Non-mandatory signing - just turn off if this is the first bad packet.. */
			DEBUG(5, ("srv_check_incoming_message: signing negotiated but not required and peer\n"
				  "isn't sending correct signatures. Turning off.\n"));
			si->negotiated_smb_signing = False;
			si->allow_smb_signing = False;
			si->doing_signing = False;
			free_signing_context(si);
			return True;
		} else if (!must_be_ok) {
			/* This packet is known to be unsigned */
			return True;
		} else {
			/* Mandatory signing or bad packet after signing started - fail and disconnect. */
			if (seq)
				DEBUG(0, ("signing_good: BAD SIG: seq %u\n", (unsigned int)seq));
			return False;
		}
	}
	return True;
}	

/***********************************************************
 SMB signing - Simple implementation - calculate a MAC on the packet
************************************************************/

static void simple_packet_signature(struct smb_basic_signing_context *data, 
				    const uchar *buf, uint32 seq_number, 
				    unsigned char calc_md5_mac[16])
{
	const size_t offset_end_of_sig = (smb_ss_field + 8);
	unsigned char sequence_buf[8];
	struct MD5Context md5_ctx;

	/*
	 * Firstly put the sequence number into the first 4 bytes.
	 * and zero out the next 4 bytes.
	 *
	 * We do this here, to avoid modifying the packet.
	 */

	DEBUG(10,("simple_packet_signature: sequence number %u\n", seq_number ));

	SIVAL(sequence_buf, 0, seq_number);
	SIVAL(sequence_buf, 4, 0);

	/* Calculate the 16 byte MAC - but don't alter the data in the
	   incoming packet.
	   
	   This makes for a bit of fussing about, but it's not too bad.
	*/
	MD5Init(&md5_ctx);

	/* intialise with the key */
	MD5Update(&md5_ctx, data->mac_key.data, 
		  data->mac_key.length); 

	/* copy in the first bit of the SMB header */
	MD5Update(&md5_ctx, buf + 4, smb_ss_field - 4);

	/* copy in the sequence number, instead of the signature */
	MD5Update(&md5_ctx, sequence_buf, sizeof(sequence_buf));

	/* copy in the rest of the packet in, skipping the signature */
	MD5Update(&md5_ctx, buf + offset_end_of_sig, 
		  smb_len(buf) - (offset_end_of_sig - 4));

	/* calculate the MD5 sig */ 
	MD5Final(calc_md5_mac, &md5_ctx);
}


/***********************************************************
 SMB signing - Client implementation - send the MAC.
************************************************************/

static void client_sign_outgoing_message(char *outbuf, struct smb_sign_info *si)
{
	unsigned char calc_md5_mac[16];
	struct smb_basic_signing_context *data = si->signing_context;
	uint32 send_seq_num;

	if (!si->doing_signing)
		return;

	/* JRA Paranioa test - we should be able to get rid of this... */
	if (smb_len(outbuf) < (smb_ss_field + 8 - 4)) {
		DEBUG(1, ("client_sign_outgoing_message: Logic error. Can't check signature on short packet! smb_len = %u\n",
					smb_len(outbuf) ));
		abort();
	}

	/* mark the packet as signed - BEFORE we sign it...*/
	mark_packet_signed(outbuf);

	if (data->trans_info)
		send_seq_num = data->trans_info->send_seq_num;
	else
		send_seq_num = data->send_seq_num;

	simple_packet_signature(data, (const unsigned char *)outbuf, send_seq_num, calc_md5_mac);

	DEBUG(10, ("client_sign_outgoing_message: sent SMB signature of\n"));
	dump_data(10, (const char *)calc_md5_mac, 8);

	memcpy(&outbuf[smb_ss_field], calc_md5_mac, 8);

/*	cli->outbuf[smb_ss_field+2]=0; 
	Uncomment this to test if the remote server actually verifies signatures...*/

	if (data->trans_info)
		return;

	data->send_seq_num++;
	store_sequence_for_reply(&data->outstanding_packet_list, 
				 SVAL(outbuf,smb_mid), data->send_seq_num);
	data->send_seq_num++;
}

/***********************************************************
 SMB signing - Client implementation - check a MAC sent by server.
************************************************************/

static BOOL client_check_incoming_message(char *inbuf, struct smb_sign_info *si, BOOL must_be_ok)
{
	BOOL good;
	uint32 reply_seq_number;
	uint32 saved_seq;
	unsigned char calc_md5_mac[16];
	unsigned char *server_sent_mac;

	struct smb_basic_signing_context *data = si->signing_context;

	if (!si->doing_signing)
		return True;

	if (smb_len(inbuf) < (smb_ss_field + 8 - 4)) {
		DEBUG(1, ("client_check_incoming_message: Can't check signature on short packet! smb_len = %u\n", smb_len(inbuf)));
		return False;
	}

	if (data->trans_info) {
		reply_seq_number = data->trans_info->reply_seq_num;
	} else if (!get_sequence_for_reply(&data->outstanding_packet_list, 
				    SVAL(inbuf, smb_mid), &reply_seq_number)) {
		DEBUG(1, ("client_check_incoming_message: failed to get sequence number %u for reply.\n",
					(unsigned int) SVAL(inbuf, smb_mid) ));
		return False;
	}

	saved_seq = reply_seq_number;
	simple_packet_signature(data, (const unsigned char *)inbuf, reply_seq_number, calc_md5_mac);

	server_sent_mac = (unsigned char *)&inbuf[smb_ss_field];
	good = (memcmp(server_sent_mac, calc_md5_mac, 8) == 0);
	
	if (!good) {
		DEBUG(5, ("client_check_incoming_message: BAD SIG: wanted SMB signature of\n"));
		dump_data(5, (const char *)calc_md5_mac, 8);
		
		DEBUG(5, ("client_check_incoming_message: BAD SIG: got SMB signature of\n"));
		dump_data(5, (const char *)server_sent_mac, 8);
#if 1 /* JRATEST */
		{
			int i;
			reply_seq_number -= 5;
			for (i = 0; i < 10; i++, reply_seq_number++) {
				simple_packet_signature(data, (const unsigned char *)inbuf, reply_seq_number, calc_md5_mac);
				if (memcmp(server_sent_mac, calc_md5_mac, 8) == 0) {
					DEBUG(0,("client_check_incoming_message: out of seq. seq num %u matches. \
We were expecting seq %u\n", reply_seq_number, saved_seq ));
					break;
				}
			}
		}
#endif /* JRATEST */

	} else {
		DEBUG(10, ("client_check_incoming_message: seq %u: got good SMB signature of\n", (unsigned int)reply_seq_number));
		dump_data(10, (const char *)server_sent_mac, 8);
	}
	return signing_good(inbuf, si, good, saved_seq, must_be_ok);
}

/***********************************************************
 SMB signing - Simple implementation - free signing context
************************************************************/

static void simple_free_signing_context(struct smb_sign_info *si)
{
	struct smb_basic_signing_context *data = si->signing_context;
	struct outstanding_packet_lookup *list = data->outstanding_packet_list;
	
	while (list) {
		struct outstanding_packet_lookup *old_head = list;
		DLIST_REMOVE(list, list);
		SAFE_FREE(old_head);
	}

	data_blob_free(&data->mac_key);

	if (data->trans_info)
		SAFE_FREE(data->trans_info);

	SAFE_FREE(si->signing_context);

	return;
}

/***********************************************************
 SMB signing - Simple implementation - setup the MAC key.
************************************************************/

BOOL cli_simple_set_signing(struct cli_state *cli,
			    const DATA_BLOB user_session_key,
			    const DATA_BLOB response)
{
	struct smb_basic_signing_context *data;

	if (!user_session_key.length)
		return False;

	if (!cli_set_smb_signing_common(cli)) {
		return False;
	}

	if (!set_smb_signing_real_common(&cli->sign_info)) {
		return False;
	}

	data = smb_xmalloc(sizeof(*data));
	memset(data, '\0', sizeof(*data));

	cli->sign_info.signing_context = data;
	
	data->mac_key = data_blob(NULL, response.length + user_session_key.length);

	memcpy(&data->mac_key.data[0], user_session_key.data, user_session_key.length);

	DEBUG(10, ("cli_simple_set_signing: user_session_key\n"));
	dump_data(10, (const char *)user_session_key.data, user_session_key.length);

	if (response.length) {
		memcpy(&data->mac_key.data[user_session_key.length],response.data, response.length);
		DEBUG(10, ("cli_simple_set_signing: response_data\n"));
		dump_data(10, (const char *)response.data, response.length);
	} else {
		DEBUG(10, ("cli_simple_set_signing: NULL response_data\n"));
	}

	dump_data_pw("MAC ssession key is:\n", data->mac_key.data, data->mac_key.length);

	/* Initialise the sequence number */
	data->send_seq_num = 0;

	/* Initialise the list of outstanding packets */
	data->outstanding_packet_list = NULL;

	cli->sign_info.sign_outgoing_message = client_sign_outgoing_message;
	cli->sign_info.check_incoming_message = client_check_incoming_message;
	cli->sign_info.free_signing_context = simple_free_signing_context;

	return True;
}

/***********************************************************
 Tell client code we are in a multiple trans reply state.
 We call this after the last outgoing trans2 packet (which
 has incremented the sequence numbers), so we must save the
 current mid and sequence number -2.
************************************************************/

void cli_signing_trans_start(struct cli_state *cli, uint16 mid)
{
	struct smb_basic_signing_context *data = cli->sign_info.signing_context;

	if (!cli->sign_info.doing_signing || !data)
		return;

	data->trans_info = smb_xmalloc(sizeof(struct trans_info_context));
	ZERO_STRUCTP(data->trans_info);

	data->trans_info->send_seq_num = data->send_seq_num-2;
	data->trans_info->mid = mid;
	data->trans_info->reply_seq_num = data->send_seq_num-1;

	DEBUG(10,("cli_signing_trans_start: storing mid = %u, reply_seq_num = %u, send_seq_num = %u \
data->send_seq_num = %u\n",
			(unsigned int)data->trans_info->mid,
			(unsigned int)data->trans_info->reply_seq_num,
			(unsigned int)data->trans_info->send_seq_num,
			(unsigned int)data->send_seq_num ));
}

/***********************************************************
 Tell client code we are out of a multiple trans reply state.
************************************************************/

void cli_signing_trans_stop(struct cli_state *cli)
{
	struct smb_basic_signing_context *data = cli->sign_info.signing_context;

	if (!cli->sign_info.doing_signing || !data)
		return;

	DEBUG(10,("cli_signing_trans_stop: freeing mid = %u, reply_seq_num = %u, send_seq_num = %u \
data->send_seq_num = %u\n",
			(unsigned int)data->trans_info->mid,
			(unsigned int)data->trans_info->reply_seq_num,
			(unsigned int)data->trans_info->send_seq_num,
			(unsigned int)data->send_seq_num ));

	SAFE_FREE(data->trans_info);
	data->trans_info = NULL;
}

/***********************************************************
 SMB signing - TEMP implementation - calculate a MAC to send.
************************************************************/

static void temp_sign_outgoing_message(char *outbuf, struct smb_sign_info *si)
{
	/* mark the packet as signed - BEFORE we sign it...*/
	mark_packet_signed(outbuf);

	/* I wonder what BSRSPYL stands for - but this is what MS 
	   actually sends! */
	memcpy(&outbuf[smb_ss_field], "BSRSPYL ", 8);
	return;
}

/***********************************************************
 SMB signing - TEMP implementation - check a MAC sent by server.
************************************************************/

static BOOL temp_check_incoming_message(char *inbuf, struct smb_sign_info *si, BOOL foo)
{
	return True;
}

/***********************************************************
 SMB signing - TEMP implementation - free signing context
************************************************************/

static void temp_free_signing_context(struct smb_sign_info *si)
{
	return;
}

/***********************************************************
 SMB signing - NULL implementation - setup the MAC key.
************************************************************/

BOOL cli_null_set_signing(struct cli_state *cli)
{
	return null_set_signing(&cli->sign_info);
}

/***********************************************************
 SMB signing - temp implementation - setup the MAC key.
************************************************************/

BOOL cli_temp_set_signing(struct cli_state *cli)
{
	if (!cli_set_smb_signing_common(cli)) {
		return False;
	}

	cli->sign_info.signing_context = NULL;
	
	cli->sign_info.sign_outgoing_message = temp_sign_outgoing_message;
	cli->sign_info.check_incoming_message = temp_check_incoming_message;
	cli->sign_info.free_signing_context = temp_free_signing_context;

	return True;
}

void cli_free_signing_context(struct cli_state *cli)
{
	free_signing_context(&cli->sign_info);
}

/**
 * Sign a packet with the current mechanism
 */
 
void cli_calculate_sign_mac(struct cli_state *cli)
{
	cli->sign_info.sign_outgoing_message(cli->outbuf, &cli->sign_info);
}

/**
 * Check a packet with the current mechanism
 * @return False if we had an established signing connection
 *         which had a bad checksum, True otherwise.
 */
 
BOOL cli_check_sign_mac(struct cli_state *cli, BOOL must_be_ok) 
{
	if (!cli->sign_info.check_incoming_message(cli->inbuf, &cli->sign_info, must_be_ok)) {
		free_signing_context(&cli->sign_info);	
		return False;
	}
	return True;
}

/***********************************************************
 SMB signing - Server implementation - send the MAC.
************************************************************/

static void srv_sign_outgoing_message(char *outbuf, struct smb_sign_info *si)
{
	unsigned char calc_md5_mac[16];
	struct smb_basic_signing_context *data = si->signing_context;
	uint32 send_seq_number = data->send_seq_num;
	BOOL was_deferred_packet = False;
	uint16 mid;

	if (!si->doing_signing) {
		return;
	}

	/* JRA Paranioa test - we should be able to get rid of this... */
	if (smb_len(outbuf) < (smb_ss_field + 8 - 4)) {
		DEBUG(1, ("srv_sign_outgoing_message: Logic error. Can't send signature on short packet! smb_len = %u\n",
					smb_len(outbuf) ));
		abort();
	}

	/* mark the packet as signed - BEFORE we sign it...*/
	mark_packet_signed(outbuf);

	mid = SVAL(outbuf, smb_mid);

	/* See if this is a reply for a deferred packet. */
	was_deferred_packet = get_sequence_for_reply(&data->outstanding_packet_list, mid, &send_seq_number);

	if (data->trans_info && (data->trans_info->mid == mid)) {
		/* This is a reply in a trans stream. Use the sequence
		 * number associated with the stream mid. */
		send_seq_number = data->trans_info->send_seq_num;
	}

	simple_packet_signature(data, (const unsigned char *)outbuf, send_seq_number, calc_md5_mac);

	DEBUG(10, ("srv_sign_outgoing_message: seq %u: sent SMB signature of\n", (unsigned int)send_seq_number));
	dump_data(10, (const char *)calc_md5_mac, 8);

	memcpy(&outbuf[smb_ss_field], calc_md5_mac, 8);

/*	cli->outbuf[smb_ss_field+2]=0; 
	Uncomment this to test if the remote client actually verifies signatures...*/

	/* Don't mess with the sequence number for a deferred packet. */
	if (was_deferred_packet) {
		return;
	}

	if (!data->trans_info) {
		/* Always increment if not in a trans stream. */
		data->send_seq_num++;
	} else if ((data->trans_info->send_seq_num == data->send_seq_num) || (data->trans_info->mid != mid)) {
		/* Increment if this is the first reply in a trans stream or a
		 * packet that doesn't belong to this stream (different mid). */
		data->send_seq_num++;
	}
}

/***********************************************************
 Is an incoming packet an oplock break reply ?
************************************************************/

static BOOL is_oplock_break(char *inbuf)
{
	if (CVAL(inbuf,smb_com) != SMBlockingX)
		return False;

	if (!(CVAL(inbuf,smb_vwv3) & LOCKING_ANDX_OPLOCK_RELEASE))
		return False;

	DEBUG(10,("is_oplock_break: Packet is oplock break\n"));
	return True;
}

/***********************************************************
 SMB signing - Server implementation - check a MAC sent by server.
************************************************************/

static BOOL srv_check_incoming_message(char *inbuf, struct smb_sign_info *si, BOOL must_be_ok)
{
	BOOL good;
	struct smb_basic_signing_context *data = si->signing_context;
	uint32 reply_seq_number = data->send_seq_num;
	uint32 saved_seq;
	unsigned char calc_md5_mac[16];
	unsigned char *server_sent_mac;
	uint mid;

	if (!si->doing_signing)
		return True;

	if (smb_len(inbuf) < (smb_ss_field + 8 - 4)) {
		DEBUG(1, ("srv_check_incoming_message: Can't check signature on short packet! smb_len = %u\n", smb_len(inbuf)));
		return False;
	}

	mid = SVAL(inbuf, smb_mid);

	/* Is this part of a trans stream ? */
	if (data->trans_info && (data->trans_info->mid == mid)) {
		/* If so we don't increment the sequence. */
		reply_seq_number = data->trans_info->reply_seq_num;
	} else {
		/* We always increment the sequence number. */
		data->send_seq_num++;

		/* If we get an asynchronous oplock break reply and there
		 * isn't a reply pending we need to re-sync the sequence
		 * number.
		 */
		if (is_oplock_break(inbuf)) {
			DEBUG(10,("srv_check_incoming_message: oplock break at seq num %u\n", data->send_seq_num));
			data->send_seq_num++;
		}
	}

	saved_seq = reply_seq_number;
	simple_packet_signature(data, (const unsigned char *)inbuf, reply_seq_number, calc_md5_mac);

	server_sent_mac = (unsigned char *)&inbuf[smb_ss_field];
	good = (memcmp(server_sent_mac, calc_md5_mac, 8) == 0);
	
	if (!good) {

		DEBUG(5, ("srv_check_incoming_message: BAD SIG: seq %u wanted SMB signature of\n",
					(unsigned int)saved_seq));
		dump_data(5, (const char *)calc_md5_mac, 8);
		
		DEBUG(5, ("srv_check_incoming_message: BAD SIG: seq %u got SMB signature of\n",
					(unsigned int)saved_seq));
		dump_data(5, (const char *)server_sent_mac, 8);

#if 1 /* JRATEST */
		{
			int i;
			reply_seq_number -= 5;
			for (i = 0; i < 10; i++, reply_seq_number++) {
				simple_packet_signature(data, (const unsigned char *)inbuf, reply_seq_number, calc_md5_mac);
				if (memcmp(server_sent_mac, calc_md5_mac, 8) == 0) {
					DEBUG(0,("srv_check_incoming_message: out of seq. seq num %u matches. \
We were expecting seq %u\n", reply_seq_number, saved_seq ));
					break;
				}
			}
		}
#endif /* JRATEST */

	} else {
		DEBUG(10, ("srv_check_incoming_message: seq %u: (current is %u) got good SMB signature of\n", (unsigned int)reply_seq_number, (unsigned int)data->send_seq_num));
		dump_data(10, (const char *)server_sent_mac, 8);
	}

	return (signing_good(inbuf, si, good, saved_seq, must_be_ok));
}

/***********************************************************
 SMB signing - server API's.
************************************************************/

static struct smb_sign_info srv_sign_info = {
	null_sign_outgoing_message,
	null_check_incoming_message,
	null_free_signing_context,
	NULL,
	False,
	False,
	False,
	False
};

/***********************************************************
 Turn signing off or on for oplock break code.
************************************************************/

BOOL srv_oplock_set_signing(BOOL onoff)
{
	BOOL ret = srv_sign_info.doing_signing;
	srv_sign_info.doing_signing = onoff;
	return ret;
}

/***********************************************************
 Called to validate an incoming packet from the client.
************************************************************/

BOOL srv_check_sign_mac(char *inbuf, BOOL must_be_ok)
{
	/* Check if it's a session keepalive. */
	if(CVAL(inbuf,0) == SMBkeepalive)
		return True;

	return srv_sign_info.check_incoming_message(inbuf, &srv_sign_info, must_be_ok);
}

/***********************************************************
 Called to sign an outgoing packet to the client.
************************************************************/

void srv_calculate_sign_mac(char *outbuf)
{
	/* Check if it's a session keepalive. */
	/* JRA Paranioa test - do we ever generate these in the server ? */
	if(CVAL(outbuf,0) == SMBkeepalive)
		return;

	srv_sign_info.sign_outgoing_message(outbuf, &srv_sign_info);
}

/***********************************************************
 Called by server to defer an outgoing packet.
************************************************************/

void srv_defer_sign_response(uint16 mid)
{
	struct smb_basic_signing_context *data;

	if (!srv_sign_info.doing_signing)
		return;

	data = (struct smb_basic_signing_context *)srv_sign_info.signing_context;

	if (!data)
		return;

	store_sequence_for_reply(&data->outstanding_packet_list, 
				 mid, data->send_seq_num);
	data->send_seq_num++;
}

/***********************************************************
 Called to remove sequence records when a deferred packet is
 cancelled by mid. This should never find one....
************************************************************/

void srv_cancel_sign_response(uint16 mid)
{
	struct smb_basic_signing_context *data;
	uint32 dummy_seq;

	if (!srv_sign_info.doing_signing)
		return;

	data = (struct smb_basic_signing_context *)srv_sign_info.signing_context;

	if (!data)
		return;

	DEBUG(10,("srv_cancel_sign_response: for mid %u\n", (unsigned int)mid ));

	while (get_sequence_for_reply(&data->outstanding_packet_list, mid, &dummy_seq))
		;
}

/***********************************************************
 Called by server negprot when signing has been negotiated.
************************************************************/

void srv_set_signing_negotiated(void)
{
	srv_sign_info.allow_smb_signing = True;
	srv_sign_info.negotiated_smb_signing = True;
	if (lp_server_signing() == Required)
		srv_sign_info.mandatory_signing = True;

	srv_sign_info.sign_outgoing_message = temp_sign_outgoing_message;
	srv_sign_info.check_incoming_message = temp_check_incoming_message;
	srv_sign_info.free_signing_context = temp_free_signing_context;
}

/***********************************************************
 Returns whether signing is active. We can't use sendfile or raw
 reads/writes if it is.
************************************************************/

BOOL srv_is_signing_active(void)
{
	return srv_sign_info.doing_signing;
}


/***********************************************************
 Returns whether signing is negotiated. We can't use it unless it was
 in the negprot.  
************************************************************/

BOOL srv_is_signing_negotiated(void)
{
	return srv_sign_info.negotiated_smb_signing;
}

/***********************************************************
 Returns whether signing is actually happening
************************************************************/

BOOL srv_signing_started(void)
{
	struct smb_basic_signing_context *data;

	if (!srv_sign_info.doing_signing) {
		return False;
	}

	data = (struct smb_basic_signing_context *)srv_sign_info.signing_context;
	if (!data)
		return False;

	if (data->send_seq_num == 0) {
		return False;
	}

	return True;
}


/***********************************************************
 Tell server code we are in a multiple trans reply state.
************************************************************/

void srv_signing_trans_start(uint16 mid)
{
	struct smb_basic_signing_context *data;

	if (!srv_sign_info.doing_signing)
		return;

	data = (struct smb_basic_signing_context *)srv_sign_info.signing_context;
	if (!data)
		return;

	data->trans_info = smb_xmalloc(sizeof(struct trans_info_context));
	ZERO_STRUCTP(data->trans_info);

	data->trans_info->reply_seq_num = data->send_seq_num-1;
	data->trans_info->mid = mid;
	data->trans_info->send_seq_num = data->send_seq_num;

	DEBUG(10,("srv_signing_trans_start: storing mid = %u, reply_seq_num = %u, send_seq_num = %u \
data->send_seq_num = %u\n",
			(unsigned int)mid,
			(unsigned int)data->trans_info->reply_seq_num,
			(unsigned int)data->trans_info->send_seq_num,
			(unsigned int)data->send_seq_num ));
}

/***********************************************************
 Tell server code we are out of a multiple trans reply state.
************************************************************/

void srv_signing_trans_stop(void)
{
	struct smb_basic_signing_context *data;

	if (!srv_sign_info.doing_signing)
		return;

	data = (struct smb_basic_signing_context *)srv_sign_info.signing_context;
	if (!data || !data->trans_info)
		return;

	DEBUG(10,("srv_signing_trans_stop: removing mid = %u, reply_seq_num = %u, send_seq_num = %u \
data->send_seq_num = %u\n",
			(unsigned int)data->trans_info->mid,
			(unsigned int)data->trans_info->reply_seq_num,
			(unsigned int)data->trans_info->send_seq_num,
			(unsigned int)data->send_seq_num ));

	SAFE_FREE(data->trans_info);
	data->trans_info = NULL;
}

/***********************************************************
 Turn on signing from this packet onwards. 
************************************************************/

void srv_set_signing(const DATA_BLOB user_session_key, const DATA_BLOB response)
{
	struct smb_basic_signing_context *data;

	if (!user_session_key.length)
		return;

	if (!srv_sign_info.negotiated_smb_signing && !srv_sign_info.mandatory_signing) {
		DEBUG(5,("srv_set_signing: signing negotiated = %u, mandatory_signing = %u. Not allowing smb signing.\n",
			(unsigned int)srv_sign_info.negotiated_smb_signing,
			(unsigned int)srv_sign_info.mandatory_signing ));
		return;
	}

	/* Once we've turned on, ignore any more sessionsetups. */
	if (srv_sign_info.doing_signing) {
		return;
	}
	
	if (srv_sign_info.free_signing_context)
		srv_sign_info.free_signing_context(&srv_sign_info);
	
	srv_sign_info.doing_signing = True;

	data = smb_xmalloc(sizeof(*data));
	memset(data, '\0', sizeof(*data));

	srv_sign_info.signing_context = data;
	
	data->mac_key = data_blob(NULL, response.length + user_session_key.length);

	memcpy(&data->mac_key.data[0], user_session_key.data, user_session_key.length);
	if (response.length)
		memcpy(&data->mac_key.data[user_session_key.length],response.data, response.length);

	dump_data_pw("MAC ssession key is:\n", data->mac_key.data, data->mac_key.length);

	DEBUG(3,("srv_set_signing: turning on SMB signing: signing negotiated = %s, mandatory_signing = %s.\n",
				BOOLSTR(srv_sign_info.negotiated_smb_signing),
			 	BOOLSTR(srv_sign_info.mandatory_signing) ));

	/* Initialise the sequence number */
	data->send_seq_num = 0;

	/* Initialise the list of outstanding packets */
	data->outstanding_packet_list = NULL;

	srv_sign_info.sign_outgoing_message = srv_sign_outgoing_message;
	srv_sign_info.check_incoming_message = srv_check_incoming_message;
	srv_sign_info.free_signing_context = simple_free_signing_context;
}
