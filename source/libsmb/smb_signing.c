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

struct smb_basic_signing_context {
	DATA_BLOB mac_key;
	uint32 send_seq_num;
	uint32 reply_seq_num;
};

/***********************************************************
 SMB signing - Common code before we set a new signing implementation
************************************************************/

static BOOL set_smb_signing_common(struct cli_state *cli) 
{
	if (cli->sign_info.doing_signing) {
		return False;
	}
	
	if (cli->sign_info.free_signing_context)
		cli->sign_info.free_signing_context(cli);

	/* These calls are INCONPATIBLE with SMB signing */
	cli->readbraw_supported = False;
	cli->writebraw_supported = False;
	
	return True;
}

/***********************************************************
 SMB signing - Common code for 'real' implementations
************************************************************/

static BOOL set_smb_signing_real_common(struct cli_state *cli) 
{
	if (cli->sign_info.mandetory_signing) {
		DEBUG(5, ("Mandetory SMB signing enabled!\n"));
		cli->sign_info.doing_signing = True;
	}

	DEBUG(5, ("SMB signing enabled!\n"));

	return True;
}

static void mark_packet_signed(struct cli_state *cli) 
{
	uint16 flags2;
	flags2 = SVAL(cli->outbuf,smb_flg2);
	flags2 |= FLAGS2_SMB_SECURITY_SIGNATURES;
	SSVAL(cli->outbuf,smb_flg2, flags2);
}

/***********************************************************
 SMB signing - Simple implementation - calculate a MAC to send.
************************************************************/

static void cli_simple_sign_outgoing_message(struct cli_state *cli)
{
	unsigned char calc_md5_mac[16];
	struct MD5Context md5_ctx;
	struct smb_basic_signing_context *data = cli->sign_info.signing_context;

	/*
	 * Firstly put the sequence number into the first 4 bytes.
	 * and zero out the next 4 bytes.
	 */
	SIVAL(cli->outbuf, smb_ss_field, 
	      data->send_seq_num);
	SIVAL(cli->outbuf, smb_ss_field + 4, 0);

	/* mark the packet as signed - BEFORE we sign it...*/
	mark_packet_signed(cli);

	/* Calculate the 16 byte MAC and place first 8 bytes into the field. */
	MD5Init(&md5_ctx);
	MD5Update(&md5_ctx, data->mac_key.data, 
		  data->mac_key.length); 
	MD5Update(&md5_ctx, cli->outbuf + 4, smb_len(cli->outbuf));
	MD5Final(calc_md5_mac, &md5_ctx);

	DEBUG(10, ("sent SMB signiture of\n"));
	dump_data(10, calc_md5_mac, 8);

	memcpy(&cli->outbuf[smb_ss_field], calc_md5_mac, 8);

/*	cli->outbuf[smb_ss_field+2]=0; 
	Uncomment this to test if the remote server actually verifies signitures...*/
	data->send_seq_num++;
	data->reply_seq_num = data->send_seq_num;
	data->send_seq_num++;
}

/***********************************************************
 SMB signing - Simple implementation - check a MAC sent by server.
************************************************************/

static BOOL cli_simple_check_incoming_message(struct cli_state *cli)
{
	BOOL good;
	unsigned char calc_md5_mac[16];
	unsigned char server_sent_mac[8];
	struct MD5Context md5_ctx;
	struct smb_basic_signing_context *data = cli->sign_info.signing_context;

	/*
	 * Firstly put the sequence number into the first 4 bytes.
	 * and zero out the next 4 bytes.
	 */

	memcpy(server_sent_mac, &cli->inbuf[smb_ss_field], sizeof(server_sent_mac));

	DEBUG(10, ("got SMB signiture of\n"));
	dump_data(10, server_sent_mac, 8);

	SIVAL(cli->inbuf, smb_ss_field, data->reply_seq_num);
	SIVAL(cli->inbuf, smb_ss_field + 4, 0);

	/* Calculate the 16 byte MAC and place first 8 bytes into the field. */
	MD5Init(&md5_ctx);
	MD5Update(&md5_ctx, data->mac_key.data, 
		  data->mac_key.length); 
	MD5Update(&md5_ctx, cli->inbuf + 4, smb_len(cli->inbuf));
	MD5Final(calc_md5_mac, &md5_ctx);

	good = (memcmp(server_sent_mac, calc_md5_mac, 8) == 0);
	
	if (good && !cli->sign_info.doing_signing) {
		cli->sign_info.doing_signing = True;
	}

	if (!good) {
		DEBUG(1, ("SMB signiture check failed!\n"));
	}

	return good;
}

/***********************************************************
 SMB signing - Simple implementation - free signing context
************************************************************/

static void cli_simple_free_signing_context(struct cli_state *cli)
{
	struct smb_basic_signing_context *data = cli->sign_info.signing_context;

	data_blob_free(&data->mac_key);
	SAFE_FREE(cli->sign_info.signing_context);

	return;
}

/***********************************************************
 SMB signing - Simple implementation - setup the MAC key.
************************************************************/

void cli_simple_set_signing(struct cli_state *cli, const uchar user_session_key[16], const DATA_BLOB response)
{
	struct smb_basic_signing_context *data;

	if (!set_smb_signing_common(cli)) {
		return;
	}

	if (!set_smb_signing_real_common(cli)) {
		return;
	}

	data = smb_xmalloc(sizeof(*data));
	cli->sign_info.signing_context = data;
	
	data->mac_key = data_blob(NULL, MIN(response.length + 16, 40));

	memcpy(&data->mac_key.data[0], user_session_key, 16);
	memcpy(&data->mac_key.data[16],response.data, MIN(response.length, 40 - 16));

	/* Initialise the sequence number */
	data->send_seq_num = 0;

	cli->sign_info.sign_outgoing_message = cli_simple_sign_outgoing_message;
	cli->sign_info.check_incoming_message = cli_simple_check_incoming_message;
	cli->sign_info.free_signing_context = cli_simple_free_signing_context;
}

/***********************************************************
 SMB signing - NULL implementation - calculate a MAC to send.
************************************************************/

static void cli_null_sign_outgoing_message(struct cli_state *cli)
{
	static uchar zeros[8];
	memcpy(&cli->outbuf[smb_ss_field], zeros, sizeof(zeros));
}

/***********************************************************
 SMB signing - NULL implementation - check a MAC sent by server.
************************************************************/

static BOOL cli_null_check_incoming_message(struct cli_state *cli)
{
	return True;
}

/***********************************************************
 SMB signing - NULL implementation - free signing context
************************************************************/

static void cli_null_free_signing_context(struct cli_state *cli)
{
	return;
}

/***********************************************************
 SMB signing - NULL implementation - setup the MAC key.
************************************************************/

void cli_null_set_signing(struct cli_state *cli)
{
	struct smb_basic_sign_data *data;

	if (!set_smb_signing_common(cli)) {
		return;
	}

	cli->sign_info.signing_context = NULL;
	
	cli->sign_info.sign_outgoing_message = cli_null_sign_outgoing_message;
	cli->sign_info.check_incoming_message = cli_null_check_incoming_message;
	cli->sign_info.free_signing_context = cli_null_free_signing_context;
}

/***********************************************************
 SMB signing - TEMP implementation - calculate a MAC to send.
************************************************************/

static void cli_temp_sign_outgoing_message(struct cli_state *cli)
{
	memcpy(&cli->outbuf[smb_ss_field], "SignRequest", 8);
	return;
}

/***********************************************************
 SMB signing - TEMP implementation - check a MAC sent by server.
************************************************************/

static BOOL cli_temp_check_incoming_message(struct cli_state *cli)
{
	return True;
}

/***********************************************************
 SMB signing - TEMP implementation - free signing context
************************************************************/

static void cli_temp_free_signing_context(struct cli_state *cli)
{
	return;
}

/***********************************************************
 SMB signing - NULL implementation - setup the MAC key.
************************************************************/

void cli_temp_set_signing(struct cli_state *cli)
{
	if (!set_smb_signing_common(cli)) {
		return;
	}

	cli->sign_info.signing_context = NULL;
	
	cli->sign_info.sign_outgoing_message = cli_temp_sign_outgoing_message;
	cli->sign_info.check_incoming_message = cli_temp_check_incoming_message;
	cli->sign_info.free_signing_context = cli_temp_free_signing_context;
}

/**
 *  Free the singing context
 */
 
void cli_free_signing_context(struct cli_state *cli) 
{
	if (cli->sign_info.free_signing_context) 
		cli->sign_info.free_signing_context(cli);

	cli_null_set_signing(cli);
}

void cli_caclulate_sign_mac(struct cli_state *cli)
{
	cli->sign_info.sign_outgoing_message(cli);
}

BOOL cli_check_sign_mac(struct cli_state *cli) 
{
	BOOL good;
	good = cli->sign_info.check_incoming_message(cli);
	
	if (!good) {
		if (cli->sign_info.doing_signing) {
			return False;
		} else {
			cli_free_signing_context(cli);	
		}
	}

	return True;
}

