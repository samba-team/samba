/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                  1997-1998.
 *  Copyright (C) Jeremy Allison                    1999.
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

/****************************************************************************
do a REG Open Policy
****************************************************************************/
BOOL do_reg_connect(struct cli_state *cli, char *full_keyname, char *key_name,
				POLICY_HND *reg_hnd)
{
	BOOL res = True;
	uint32 reg_type = 0;

	if (full_keyname == NULL)
		return False;

	ZERO_STRUCTP(reg_hnd);

	/*
	 * open registry receive a policy handle
	 */

	if (!reg_split_key(full_keyname, &reg_type, key_name)) {
		DEBUG(0,("do_reg_connect: unrecognised key name %s\n", full_keyname));	
		return False;
	}

	switch (reg_type) {
	case HKEY_LOCAL_MACHINE:
		res = res ? do_reg_open_hklm(cli, 0x84E0, 0x02000000, reg_hnd) : False;
		break;
	
	case HKEY_USERS:
		res = res ? do_reg_open_hku(cli, 0x84E0, 0x02000000, reg_hnd) : False;
		break;

	default:
		DEBUG(0,("do_reg_connect: unrecognised hive key\n"));	
		return False;
	}

	return res;
}

/****************************************************************************
do a REG Open Policy
****************************************************************************/
BOOL do_reg_open_hklm(struct cli_state *cli, uint16 unknown_0, uint32 level,
				POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_OPEN_HKLM q_o;
	REG_R_OPEN_HKLM r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_OPEN_HKLM */

	DEBUG(4,("REG Open HKLM\n"));

	init_reg_q_open_hklm(&q_o, unknown_0, level);

	/* turn parameters into data stream */
	if(!reg_io_q_open_hklm("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_OPEN_HKLM, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_open_hklm("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_OPEN_HKLM: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	/* ok, at last: we're happy. return the policy handle */
	*hnd = r_o.pol;

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Open HKU
****************************************************************************/
BOOL do_reg_open_hku(struct cli_state *cli, uint16 unknown_0, uint32 level,
				POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_OPEN_HKU q_o;
	REG_R_OPEN_HKU r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_OPEN_HKU */

	DEBUG(4,("REG Open HKU\n"));

	init_reg_q_open_hku(&q_o, unknown_0, level);

	/* turn parameters into data stream */
	if(!reg_io_q_open_hku("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, REG_OPEN_HKU, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_open_hku("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_OPEN_HKU: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	/* ok, at last: we're happy. return the policy handle */
	*hnd = r_o.pol;

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Unknown 0xB command.  sent after a create key or create value.
this might be some sort of "sync" or "refresh" command, sent after
modification of the registry...
****************************************************************************/
BOOL do_reg_flush_key(struct cli_state *cli, POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_FLUSH_KEY q_o;
	REG_R_FLUSH_KEY r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_FLUSH_KEY */

	DEBUG(4,("REG Unknown 0xB\n"));

	init_reg_q_flush_key(&q_o, hnd);

	/* turn parameters into data stream */
	if(!reg_io_q_flush_key("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_FLUSH_KEY, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_flush_key("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_FLUSH_KEY: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Query Key
****************************************************************************/
BOOL do_reg_query_key(struct cli_state *cli, POLICY_HND *hnd,
				char *class, uint32 *class_len,
				uint32 *num_subkeys, uint32 *max_subkeylen,
				uint32 *max_subkeysize, uint32 *num_values,
				uint32 *max_valnamelen, uint32 *max_valbufsize,
				uint32 *sec_desc, NTTIME *mod_time)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_QUERY_KEY q_o;
	REG_R_QUERY_KEY r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_QUERY_KEY */

	DEBUG(4,("REG Query Key\n"));

	init_reg_q_query_key(&q_o, hnd, *class_len);

	/* turn parameters into data stream */
	if(!reg_io_q_query_key("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_QUERY_KEY, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_query_key("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_QUERY_KEY: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	*class_len      = r_o.hdr_class.uni_max_len;
	rpcstr_pull(class, &r_o.uni_class, -1, -1, 0);
	*num_subkeys    = r_o.num_subkeys   ;
	*max_subkeylen  = r_o.max_subkeylen ;
	*max_subkeysize = r_o.max_subkeysize;
	*num_values     = r_o.num_values    ;
	*max_valnamelen = r_o.max_valnamelen;
	*max_valbufsize = r_o.max_valbufsize;
	*sec_desc       = r_o.sec_desc      ;
	*mod_time       = r_o.mod_time      ;

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Unknown 1A
****************************************************************************/
BOOL do_reg_unknown_1a(struct cli_state *cli, POLICY_HND *hnd, uint32 *unk)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_UNK_1A q_o;
	REG_R_UNK_1A r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_UNKNOWN_1A */

	DEBUG(4,("REG Unknown 1a\n"));

	init_reg_q_unk_1a(&q_o, hnd);

	/* turn parameters into data stream */
	if(!reg_io_q_unk_1a("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, REG_UNK_1A, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_unk_1a("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_UNK_1A: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	(*unk) = r_o.unknown;

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Query Info
****************************************************************************/
BOOL do_reg_query_info(struct cli_state *cli, POLICY_HND *hnd,
				char *key_value, uint32* key_type)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_INFO q_o;
	REG_R_INFO r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_INFO */

	DEBUG(4,("REG Query Info\n"));

	init_reg_q_info(&q_o, hnd, "ProductType");

	/* turn parameters into data stream */
	if(!reg_io_q_info("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_INFO, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_info("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if ( r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_INFO: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	/*fstrcpy(key_value, dos_buffer2_to_str(r_o.uni_val));*/
	rpcstr_pull(key_value, r_o.uni_val->buffer, sizeof(fstring), r_o.uni_val->buf_len, 0);
	*key_type = r_o.type;

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Set Key Security 
****************************************************************************/
BOOL do_reg_set_key_sec(struct cli_state *cli, POLICY_HND *hnd, SEC_DESC_BUF *sec_desc_buf)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_SET_KEY_SEC q_o;
	REG_R_SET_KEY_SEC r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_SET_KEY_SEC */

	DEBUG(4,("REG Set Key security.\n"));

	init_reg_q_set_key_sec(&q_o, hnd, sec_desc_buf);

	/* turn parameters into data stream */
	if(!reg_io_q_set_key_sec("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_SET_KEY_SEC, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_set_key_sec("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Query Key Security 
****************************************************************************/

BOOL do_reg_get_key_sec(struct cli_state *cli, POLICY_HND *hnd, uint32 *sec_buf_size, SEC_DESC_BUF **ppsec_desc_buf)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_GET_KEY_SEC q_o;
	REG_R_GET_KEY_SEC r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_GET_KEY_SEC */

	DEBUG(4,("REG query key security.  buf_size: %d\n", *sec_buf_size));

	init_reg_q_get_key_sec(&q_o, hnd, *sec_buf_size, NULL);

	/* turn parameters into data stream */
	if(!reg_io_q_get_key_sec("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_GET_KEY_SEC, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_get_key_sec("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status == 0x0000007a) {
		/*
		 * get the maximum buffer size: it was too small
		 */
		(*sec_buf_size) = r_o.hdr_sec.buf_max_len;
		DEBUG(5,("sec_buf_size too small.  use %d\n", *sec_buf_size));
	} else if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_GET_KEY_SEC: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	} else {
		(*sec_buf_size) = r_o.data->len;
		*ppsec_desc_buf = r_o.data;
	}

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Delete Value
****************************************************************************/
BOOL do_reg_delete_val(struct cli_state *cli, POLICY_HND *hnd, char *val_name)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_DELETE_VALUE q_o;
	REG_R_DELETE_VALUE r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_DELETE_VALUE */

	DEBUG(4,("REG Delete Value: %s\n", val_name));

	init_reg_q_delete_val(&q_o, hnd, val_name);

	/* turn parameters into data stream */
	if(!reg_io_q_delete_val("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, REG_DELETE_VALUE, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_delete_val("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_DELETE_VALUE: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Delete Key
****************************************************************************/
BOOL do_reg_delete_key(struct cli_state *cli, POLICY_HND *hnd, char *key_name)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_DELETE_KEY q_o;
	REG_R_DELETE_KEY r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_DELETE_KEY */

	DEBUG(4,("REG Delete Key: %s\n", key_name));

	init_reg_q_delete_key(&q_o, hnd, key_name);

	/* turn parameters into data stream */
	if(!reg_io_q_delete_key("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_DELETE_KEY, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_delete_key("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_DELETE_KEY: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Create Key
****************************************************************************/
BOOL do_reg_create_key(struct cli_state *cli, POLICY_HND *hnd,
				char *key_name, char *key_class,
				SEC_ACCESS *sam_access,
				POLICY_HND *key)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_CREATE_KEY q_o;
	REG_R_CREATE_KEY r_o;
	SEC_DESC *sec = NULL;
	SEC_DESC_BUF *sec_buf = NULL;
	size_t sec_len;

	ZERO_STRUCT(q_o);

	if (hnd == NULL)
		return False;

	/* create and send a MSRPC command with api REG_CREATE_KEY */

	DEBUG(4,("REG Create Key: %s %s 0x%08x\n", key_name, key_class,
		sam_access != NULL ? sam_access->mask : 0));

	if((sec = make_sec_desc( cli->mem_ctx, 1, NULL, NULL, NULL, NULL, &sec_len)) == NULL) {
		DEBUG(0,("make_sec_desc : malloc fail.\n"));
		return False;
	}

	DEBUG(10,("make_sec_desc: len = %d\n", (int)sec_len));

	if((sec_buf = make_sec_desc_buf( cli->mem_ctx, (int)sec_len, sec)) == NULL) {
		DEBUG(0,("make_sec_desc : malloc fail (1)\n"));
		return False;
	}

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	init_reg_q_create_key(&q_o, hnd, key_name, key_class, sam_access, sec_buf);

	/* turn parameters into data stream */
	if(!reg_io_q_create_key("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, REG_CREATE_KEY, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_create_key("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_CREATE_KEY: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	*key = r_o.key_pol;

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Enum Key
****************************************************************************/
BOOL do_reg_enum_key(struct cli_state *cli, POLICY_HND *hnd,
				int key_index, char *key_name,
				uint32 *unk_1, uint32 *unk_2,
				time_t *mod_time)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_ENUM_KEY q_o;
	REG_R_ENUM_KEY r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_ENUM_KEY */

	DEBUG(4,("REG Enum Key\n"));

	init_reg_q_enum_key(&q_o, hnd, key_index);

	/* turn parameters into data stream */
	if(!reg_io_q_enum_key("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_ENUM_KEY, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_enum_key("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_ENUM_KEY: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	(*unk_1) = r_o.unknown_1;
	(*unk_2) = r_o.unknown_2;
	rpcstr_pull(key_name, r_o.key_name.str.buffer, -1, -1, 0);
	(*mod_time) = nt_time_to_unix(&r_o.time);

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Create Value
****************************************************************************/
BOOL do_reg_create_val(struct cli_state *cli, POLICY_HND *hnd,
				char *val_name, uint32 type, BUFFER3 *data)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_CREATE_VALUE q_o;
	REG_R_CREATE_VALUE r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_CREATE_VALUE */

	DEBUG(4,("REG Create Value: %s\n", val_name));

	init_reg_q_create_val(&q_o, hnd, val_name, type, data);

	/* turn parameters into data stream */
	if(!reg_io_q_create_val("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_CREATE_VALUE, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_create_val("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_CREATE_VALUE: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Enum Value
****************************************************************************/
BOOL do_reg_enum_val(struct cli_state *cli, POLICY_HND *hnd,
				int val_index, int max_valnamelen, int max_valbufsize,
				fstring val_name,
				uint32 *val_type, BUFFER2 *value)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_ENUM_VALUE q_o;
	REG_R_ENUM_VALUE r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_ENUM_VALUE */

	DEBUG(4,("REG Enum Value\n"));

	init_reg_q_enum_val(&q_o, hnd, val_index, max_valnamelen, max_valbufsize);

	/* turn parameters into data stream */
	if(!reg_io_q_enum_val("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_ENUM_VALUE, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);
	r_o.buf_value = value;

	if(!reg_io_r_enum_val("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_ENUM_VALUE: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	(*val_type) = r_o.type;
	rpcstr_pull(val_name, &r_o.uni_name, -1, -1, 0);

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Open Key
****************************************************************************/
BOOL do_reg_open_entry(struct cli_state *cli, POLICY_HND *hnd,
				char *key_name, uint32 unk_0,
				POLICY_HND *key_hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_OPEN_ENTRY q_o;
	REG_R_OPEN_ENTRY r_o;

	if (hnd == NULL)
		return False;

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api REG_OPEN_ENTRY */

	DEBUG(4,("REG Open Entry\n"));

	init_reg_q_open_entry(&q_o, hnd, key_name, unk_0);

	/* turn parameters into data stream */
	if(!reg_io_q_open_entry("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_OPEN_ENTRY, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_o);

	if(!reg_io_r_open_entry("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_o.status != 0) {
		/* report error code */
		DEBUG(0,("REG_OPEN_ENTRY: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	*key_hnd = r_o.pol;

	prs_mem_free(&rbuf);

	return True;
}

/****************************************************************************
do a REG Close
****************************************************************************/
BOOL do_reg_close(struct cli_state *cli, POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct buf; 
	REG_Q_CLOSE q_c;
	REG_R_CLOSE r_c;

	if (hnd == NULL)
		return False;

	/* create and send a MSRPC command with api REG_CLOSE */

	prs_init(&buf, MAX_PDU_FRAG_LEN, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

	DEBUG(4,("REG Close\n"));

	/* store the parameters */
	init_reg_q_close(&q_c, hnd);

	/* turn parameters into data stream */
	if(!reg_io_q_close("", &q_c, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, REG_CLOSE, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return False;
	}

	prs_mem_free(&buf);

	ZERO_STRUCT(r_c);

	if(!reg_io_r_close("", &r_c, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return False;
	}

	if (r_c.status != 0) {
		/* report error code */
		DEBUG(0,("REG_CLOSE: %s\n", nt_errstr(r_c.status)));
		prs_mem_free(&rbuf);
		return False;
	}

	/* check that the returned policy handle is all zeros */

	if (IVAL(&r_c.pol.data1,0) || IVAL(&r_c.pol.data2,0) || SVAL(&r_c.pol.data3,0) ||
		SVAL(&r_c.pol.data4,0) || IVAL(r_c.pol.data5,0) || IVAL(r_c.pol.data5,4) ) {
			prs_mem_free(&rbuf);
			DEBUG(0,("REG_CLOSE: non-zero handle returned\n"));
			return False;
	}	

	prs_mem_free(&rbuf);

	return True;
}
