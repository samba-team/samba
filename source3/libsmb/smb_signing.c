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
	if (!cli->sign_info.negotiated_smb_signing 
	    && !cli->sign_info.mandetory_signing) {
		return False;
	}

	if (cli->sign_info.doing_signing) {
		return False;
	}
	
	if (cli->sign_info.free_signing_context)
		cli->sign_info.free_signing_context(cli);

	/* These calls are INCOMPATIBLE with SMB signing */
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
		DEBUG(5, ("Mandatory SMB signing enabled!\n"));
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

static BOOL signing_good(struct cli_state *cli, BOOL good) 
{
	DEBUG(10, ("got SMB signature of\n"));
	dump_data(10,&cli->outbuf[smb_ss_field] , 8);

	if (good && !cli->sign_info.doing_signing) {
		cli->sign_info.doing_signing = True;
	}

	if (!good) {
		if (cli->sign_info.doing_signing) {
			DEBUG(1, ("SMB signature check failed!\n"));
			return False;
		} else {
			DEBUG(3, ("Server did not sign reply correctly\n"));
			cli_free_signing_context(cli);
			return False;
		}
	}
	return True;
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

	DEBUG(10, ("sent SMB signature of\n"));
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

	DEBUG(10, ("got SMB signature of\n"));
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
	
	return signing_good(cli, good);
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

BOOL cli_simple_set_signing(struct cli_state *cli, const uchar user_session_key[16], const DATA_BLOB response)
{
	struct smb_basic_signing_context *data;

	if (!set_smb_signing_common(cli)) {
		return False;
	}

	if (!set_smb_signing_real_common(cli)) {
		return False;
	}

	data = smb_xmalloc(sizeof(*data));
	cli->sign_info.signing_context = data;
	
	data->mac_key = data_blob(NULL, MIN(response.length + 16, 40));

	memcpy(&data->mac_key.data[0], user_session_key, 16);
	memcpy(&data->mac_key.data[16],response.data, MIN(response.length, 40 - 16));

	/* Initialize the sequence number */
	data->send_seq_num = 0;

	cli->sign_info.sign_outgoing_message = cli_simple_sign_outgoing_message;
	cli->sign_info.check_incoming_message = cli_simple_check_incoming_message;
	cli->sign_info.free_signing_context = cli_simple_free_signing_context;

	return True;
}

/***********************************************************
 SMB signing - NTLMSSP implementation - calculate a MAC to send.
************************************************************/

static void cli_ntlmssp_sign_outgoing_message(struct cli_state *cli)
{
	NTSTATUS nt_status;
	DATA_BLOB sig;
	NTLMSSP_CLIENT_STATE *ntlmssp_state = cli->sign_info.signing_context;

	/* mark the packet as signed - BEFORE we sign it...*/
	mark_packet_signed(cli);
	
	nt_status = ntlmssp_client_sign_packet(ntlmssp_state, cli->outbuf + 4, 
					       smb_len(cli->outbuf), &sig);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("NTLMSSP signing failed with %s\n", nt_errstr(nt_status)));
		return;
	}

	DEBUG(10, ("sent SMB signature of\n"));
	dump_data(10, sig.data, MIN(sig.length, 8));
	memcpy(&cli->outbuf[smb_ss_field], sig.data, MIN(sig.length, 8));
	
	data_blob_free(&sig);
}

/***********************************************************
 SMB signing - NTLMSSP implementation - check a MAC sent by server.
************************************************************/

static BOOL cli_ntlmssp_check_incoming_message(struct cli_state *cli)
{
	BOOL good;
	NTSTATUS nt_status;
	DATA_BLOB sig = data_blob(&cli->outbuf[smb_ss_field], 8);

	NTLMSSP_CLIENT_STATE *ntlmssp_state = cli->sign_info.signing_context;

	nt_status = ntlmssp_client_check_packet(ntlmssp_state, cli->outbuf + 4, 
						smb_len(cli->outbuf), &sig);
	
	data_blob_free(&sig);
	
	good = NT_STATUS_IS_OK(nt_status);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(5, ("NTLMSSP signing failed with %s\n", nt_errstr(nt_status)));
	}

	return signing_good(cli, good);
}

/***********************************************************
 SMB signing - NTLMSSP implementation - free signing context
************************************************************/

static void cli_ntlmssp_free_signing_context(struct cli_state *cli)
{
	ntlmssp_client_end((NTLMSSP_CLIENT_STATE **)&cli->sign_info.signing_context);
}

/***********************************************************
 SMB signing - NTLMSSP implementation - setup the MAC key.
************************************************************/

BOOL cli_ntlmssp_set_signing(struct cli_state *cli,
			     NTLMSSP_CLIENT_STATE *ntlmssp_state)
{
	if (!set_smb_signing_common(cli)) {
		return False;
	}

	if (!NT_STATUS_IS_OK(ntlmssp_client_sign_init(ntlmssp_state))) {
		return False;
	}

	if (!set_smb_signing_real_common(cli)) {
		return False;
	}

	cli->sign_info.signing_context = ntlmssp_state;
	ntlmssp_state->ref_count++;

	cli->sign_info.sign_outgoing_message = cli_ntlmssp_sign_outgoing_message;
	cli->sign_info.check_incoming_message = cli_ntlmssp_check_incoming_message;
	cli->sign_info.free_signing_context = cli_ntlmssp_free_signing_context;

	return True;
}

/***********************************************************
 SMB signing - NULL implementation - calculate a MAC to send.
************************************************************/

static void cli_null_sign_outgoing_message(struct cli_state *cli)
{
	/* we can't zero out the sig, as we might be trying to send a
	   session request - which is NBT-level, not SMB level and doesn't
	   have the field */
	return;
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

/**
 SMB signing - NULL implementation - setup the MAC key.

 @note Used as an initialisation only - it will not correctly
       shut down a real signing mechinism
*/

BOOL cli_null_set_signing(struct cli_state *cli)
{
	cli->sign_info.signing_context = NULL;
	
	cli->sign_info.sign_outgoing_message = cli_null_sign_outgoing_message;
	cli->sign_info.check_incoming_message = cli_null_check_incoming_message;
	cli->sign_info.free_signing_context = cli_null_free_signing_context;

	return True;
}

/***********************************************************
 SMB signing - TEMP implementation - calculate a MAC to send.
************************************************************/

static void cli_temp_sign_outgoing_message(struct cli_state *cli)
{
	/* mark the packet as signed - BEFORE we sign it...*/
	mark_packet_signed(cli);

	/* I wonder what BSRSPYL stands for - but this is what MS 
	   actually sends! */
	memcpy(&cli->outbuf[smb_ss_field], "BSRSPYL ", 8);
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

BOOL cli_temp_set_signing(struct cli_state *cli)
{
	if (!set_smb_signing_common(cli)) {
		return False;
	}

	cli->sign_info.signing_context = NULL;
	
	cli->sign_info.sign_outgoing_message = cli_temp_sign_outgoing_message;
	cli->sign_info.check_incoming_message = cli_temp_check_incoming_message;
	cli->sign_info.free_signing_context = cli_temp_free_signing_context;

	return True;
}

/**
 * Free the signing context
 */
 
void cli_free_signing_context(struct cli_state *cli) 
{
	if (cli->sign_info.free_signing_context) 
		cli->sign_info.free_signing_context(cli);

	cli_null_set_signing(cli);
}

/**
 * Sign a packet with the current mechanism
 */
 
void cli_caclulate_sign_mac(struct cli_state *cli)
{
	cli->sign_info.sign_outgoing_message(cli);
}

/**
 * Check a packet with the current mechanism
 * @return False if we had an established signing connection
 *         which had a back checksum, True otherwise
 */
 
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

