/* 
   Unix SMB/CIFS implementation.
   SMB Signing Code
   Copyright (C) Jeremy Allison 2002.
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

struct smb_basic_signing_context {
	DATA_BLOB mac_key;
	uint32 send_seq_num;
	struct outstanding_packet_lookup *outstanding_packet_list;
};

static void store_sequence_for_reply(struct outstanding_packet_lookup **list, 
				     uint16 mid, uint32 reply_seq_num) 
{
	struct outstanding_packet_lookup *t;
	struct outstanding_packet_lookup *tmp;
	
	t = smb_xmalloc(sizeof(*t));
	ZERO_STRUCTP(t);

	DLIST_ADD_END(*list, t, tmp);
	t->mid = mid;
	t->reply_seq_num = reply_seq_num;
}

static BOOL get_sequence_for_reply(struct outstanding_packet_lookup **list,
				   uint16 mid, uint32 *reply_seq_num) 
{
	struct outstanding_packet_lookup *t;

	for (t = *list; t; t = t->next) {
		if (t->mid == mid) {
			*reply_seq_num = t->reply_seq_num;
			DLIST_REMOVE(*list, t);
			return True;
		}
	}
	DEBUG(0, ("Unexpected incoming packet, it's MID (%u) does not match"
		  " a MID in our outstanding list!\n", mid));
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
		si->doing_signing = True;
	}

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

static BOOL null_check_incoming_message(char *inbuf, struct smb_sign_info *si)
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


static BOOL signing_good(char *inbuf, struct smb_sign_info *si, BOOL good) 
{
	DEBUG(10, ("got SMB signature of\n"));
	dump_data(10,&inbuf[smb_ss_field] , 8);

	if (good && !si->doing_signing) {
		si->doing_signing = True;
	}

	if (!good) {
		if (si->doing_signing) {
			DEBUG(1, ("SMB signature check failed!\n"));
			return False;
		} else {
			DEBUG(3, ("Server did not sign reply correctly\n"));
			free_signing_context(si);
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

	SIVAL(sequence_buf, 0, seq_number);
	SIVAL(sequence_buf, 4, 0);

	/* Calculate the 16 byte MAC - but don't alter the data in the
	   incoming packet.
	   
	   This makes for a bit for fussing about, but it's not too bad.
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
 SMB signing - Simple implementation - send the MAC.
************************************************************/

static void cli_simple_sign_outgoing_message(char *outbuf, struct smb_sign_info *si)
{
	unsigned char calc_md5_mac[16];
	struct smb_basic_signing_context *data = si->signing_context;

	/* mark the packet as signed - BEFORE we sign it...*/
	mark_packet_signed(outbuf);

	simple_packet_signature(data, outbuf, data->send_seq_num, calc_md5_mac);

	DEBUG(10, ("sent SMB signature of\n"));
	dump_data(10, calc_md5_mac, 8);

	memcpy(&outbuf[smb_ss_field], calc_md5_mac, 8);

/*	cli->outbuf[smb_ss_field+2]=0; 
	Uncomment this to test if the remote server actually verifies signatures...*/

	data->send_seq_num++;
	store_sequence_for_reply(&data->outstanding_packet_list, 
				 SVAL(outbuf,smb_mid),
				 data->send_seq_num);
	data->send_seq_num++;
}

/***********************************************************
 SMB signing - Simple implementation - check a MAC sent by server.
************************************************************/

static BOOL cli_simple_check_incoming_message(char *inbuf, struct smb_sign_info *si)
{
	BOOL good;
	uint32 reply_seq_number;
	unsigned char calc_md5_mac[16];
	unsigned char *server_sent_mac;

	struct smb_basic_signing_context *data = si->signing_context;

	if (!get_sequence_for_reply(&data->outstanding_packet_list, 
				    SVAL(inbuf, smb_mid), 
				    &reply_seq_number)) {
		return False;
	}

	simple_packet_signature(data, inbuf, reply_seq_number, calc_md5_mac);

	server_sent_mac = &inbuf[smb_ss_field];
	good = (memcmp(server_sent_mac, calc_md5_mac, 8) == 0);
	
	if (!good) {
		DEBUG(5, ("BAD SIG: wanted SMB signature of\n"));
		dump_data(5, calc_md5_mac, 8);
		
		DEBUG(5, ("BAD SIG: got SMB signature of\n"));
		dump_data(5, server_sent_mac, 8);
	}
	return signing_good(inbuf, si, good);
}

/***********************************************************
 SMB signing - Simple implementation - free signing context
************************************************************/

static void cli_simple_free_signing_context(struct smb_sign_info *si)
{
	struct smb_basic_signing_context *data = si->signing_context;
	struct outstanding_packet_lookup *list = data->outstanding_packet_list;
	
	while (list) {
		struct outstanding_packet_lookup *old_head = list;
		DLIST_REMOVE(list, list);
		SAFE_FREE(old_head);
	}

	data_blob_free(&data->mac_key);
	SAFE_FREE(si->signing_context);

	return;
}

/***********************************************************
 SMB signing - Simple implementation - setup the MAC key.
************************************************************/

BOOL cli_simple_set_signing(struct cli_state *cli, const uchar user_session_key[16], const DATA_BLOB response)
{
	struct smb_basic_signing_context *data;

	if (!user_session_key)
		return False;

	if (!cli_set_smb_signing_common(cli)) {
		return False;
	}

	if (!set_smb_signing_real_common(&cli->sign_info)) {
		return False;
	}

	data = smb_xmalloc(sizeof(*data));

	cli->sign_info.signing_context = data;
	
	data->mac_key = data_blob(NULL, response.length + 16);

	memcpy(&data->mac_key.data[0], user_session_key, 16);
	memcpy(&data->mac_key.data[16],response.data, response.length);

	/* Initialise the sequence number */
	data->send_seq_num = 0;

	/* Initialise the list of outstanding packets */
	data->outstanding_packet_list = NULL;

	cli->sign_info.sign_outgoing_message = cli_simple_sign_outgoing_message;
	cli->sign_info.check_incoming_message = cli_simple_check_incoming_message;
	cli->sign_info.free_signing_context = cli_simple_free_signing_context;

	return True;
}

/***********************************************************
 SMB signing - TEMP implementation - calculate a MAC to send.
************************************************************/

static void cli_temp_sign_outgoing_message(char *outbuf, struct smb_sign_info *si)
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

static BOOL cli_temp_check_incoming_message(char *inbuf, struct smb_sign_info *si)
{
	return True;
}

/***********************************************************
 SMB signing - TEMP implementation - free signing context
************************************************************/

static void cli_temp_free_signing_context(struct smb_sign_info *si)
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
	
	cli->sign_info.sign_outgoing_message = cli_temp_sign_outgoing_message;
	cli->sign_info.check_incoming_message = cli_temp_check_incoming_message;
	cli->sign_info.free_signing_context = cli_temp_free_signing_context;

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
 *         which had a back checksum, True otherwise
 */
 
BOOL cli_check_sign_mac(struct cli_state *cli) 
{
	BOOL good;

	if (smb_len(cli->inbuf) < (smb_ss_field + 8 - 4)) {
		DEBUG(cli->sign_info.doing_signing ? 1 : 10, ("Can't check signature on short packet! smb_len = %u\n", smb_len(cli->inbuf)));
		good = False;
	} else {
		good = cli->sign_info.check_incoming_message(cli->inbuf, &cli->sign_info);
	}

	if (!good) {
		if (cli->sign_info.doing_signing) {
			return False;
		} else {
			free_signing_context(&cli->sign_info);	
		}
	}

	return True;
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
 Turn on signing after sending an oplock break.
************************************************************/

void srv_enable_signing(void)
{
	srv_sign_info.doing_signing = True;
}

/***********************************************************
 Turn off signing before sending an oplock break.
************************************************************/

void srv_disable_signing(void)
{
	srv_sign_info.doing_signing = False;
}

/***********************************************************
 Called to validate an incoming packet from the client.
************************************************************/

BOOL srv_check_sign_mac(char *inbuf)
{
	if (!srv_sign_info.doing_signing)
		return True;

	/* Check if it's a session keepalive. */
	if(CVAL(inbuf,0) == SMBkeepalive)
		return True;

	if (smb_len(inbuf) < (smb_ss_field + 8 - 4)) {
		DEBUG(1, ("srv_check_sign_mac: Can't check signature on short packet! smb_len = %u\n", smb_len(inbuf) ));
		return False;
	}

	return srv_sign_info.check_incoming_message(inbuf, &srv_sign_info);
}

/***********************************************************
 Called to sign an outgoing packet to the client.
************************************************************/

void srv_calculate_sign_mac(char *outbuf)
{
	if (!srv_sign_info.doing_signing)
		return;

	/* Check if it's a session keepalive. */
	/* JRA Paranioa test - do we ever generate these in the server ? */
	if(CVAL(outbuf,0) == SMBkeepalive)
		return;

	/* JRA Paranioa test - we should be able to get rid of this... */
	if (smb_len(outbuf) < (smb_ss_field + 8 - 4)) {
		DEBUG(1, ("srv_calculate_sign_mac: Logic error. Can't check signature on short packet! smb_len = %u\n",
					smb_len(outbuf) ));
		abort();
	}

	srv_sign_info.sign_outgoing_message(outbuf, &srv_sign_info);
}

/***********************************************************
 Returns whether signing is active. We can't use sendfile or raw
 reads/writes if it is.
************************************************************/

BOOL srv_signing_active(void)
{
	return srv_sign_info.doing_signing;
}
