/* 
   Unix SMB/CIFS implementation.
   RPC Pipe client
 
   Copyright (C) Andrew Tridgell              1992-2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
   Copyright (C) Paul Ashton                  1997-2000.
   Copyright (C) Jeremy Allison                    1999.
   Copyright (C) Simo Sorce                        2001
   Copyright (C) Jeremy Cooper                     2004
   
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

/* Shutdown a server */

/* internal connect to a registry hive root (open a registry policy) */

static WERROR cli_reg_open_hive_int(struct cli_state *cli,
                                      TALLOC_CTX *mem_ctx, uint16 op_code,
                                      const char *op_name,
                                      uint32 access_mask, POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_OPEN_HIVE q_o;
	REG_R_OPEN_HIVE r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	ZERO_STRUCT(q_o);
	ZERO_STRUCT(r_o);

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	init_reg_q_open_hive(&q_o, access_mask);

	/* Marshall the query parameters */
	if (!reg_io_q_open_hive("", &q_o, &qbuf, 0))
		goto done;

	/* Send the request, receive the response */
	if (!rpc_api_pipe_req(cli, PI_WINREG, op_code, &qbuf, &rbuf))
		goto done;

	/* Unmarshall the response */
	if (!reg_io_r_open_hive("", &r_o, &rbuf, 0))
		goto done;

	result = r_o.status;
	if (NT_STATUS_IS_OK(result))
		*hnd = r_o.pol;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}


WERROR cli_reg_shutdown(struct cli_state * cli, TALLOC_CTX *mem_ctx,
                          const char *msg, uint32 timeout, BOOL do_reboot,
			  BOOL force)
{
	prs_struct qbuf;
	prs_struct rbuf; 
	REG_Q_SHUTDOWN q_s;
	REG_R_SHUTDOWN r_s;
	WERROR result = WERR_GENERAL_FAILURE;

	if (msg == NULL) return WERR_INVALID_PARAM;

	ZERO_STRUCT (q_s);
	ZERO_STRUCT (r_s);

	prs_init(&qbuf , MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_shutdown(&q_s, msg, timeout, do_reboot, force);

	if (!reg_io_q_shutdown("", &q_s, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_SHUTDOWN, &qbuf, &rbuf))
		goto done;
	
	/* Unmarshall response */
	
	if(reg_io_r_shutdown("", &r_s, &rbuf, 0))
		result = r_s.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}


/* Abort a server shutdown */

WERROR cli_reg_abort_shutdown(struct cli_state * cli, TALLOC_CTX *mem_ctx)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_ABORT_SHUTDOWN q_s;
	REG_R_ABORT_SHUTDOWN r_s;
	WERROR result = WERR_GENERAL_FAILURE;

	ZERO_STRUCT (q_s);
	ZERO_STRUCT (r_s);

	prs_init(&qbuf , MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);
	
	/* Marshall data and send request */

	init_reg_q_abort_shutdown(&q_s);

	if (!reg_io_q_abort_shutdown("", &q_s, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_ABORT_SHUTDOWN, &qbuf, &rbuf))
	    	goto done;
	
	/* Unmarshall response */
	
	if (reg_io_r_abort_shutdown("", &r_s, &rbuf, 0))
		result = r_s.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf );

	return result;
}

/* connect to a registry hive root (open a registry policy) */

WERROR cli_reg_connect(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                         uint32 reg_type, uint32 access_mask,
                         POLICY_HND *reg_hnd)
{	uint16 op_code;
	const char *op_name;

	ZERO_STRUCTP(reg_hnd);

	switch (reg_type)
	{
	case HKEY_CLASSES_ROOT:
		op_code = REG_OPEN_HKCR;
		op_name = "REG_OPEN_HKCR";
		break;
	case HKEY_LOCAL_MACHINE:
		op_code = REG_OPEN_HKLM;
		op_name = "REG_OPEN_HKLM";
		break;
	case HKEY_USERS:
		op_code = REG_OPEN_HKU;
		op_name = "REG_OPEN_HKU";
		break;
	case HKEY_PERFORMANCE_DATA:
		op_code = REG_OPEN_HKPD;
		op_name = "REG_OPEN_HKPD";
		break;
	default:
		return WERR_INVALID_PARAM;
	}

	return cli_reg_open_hive_int(cli, mem_ctx, op_code, op_name,
                                     access_mask, reg_hnd);
}

/****************************************************************************
do a REG Unknown 0xB command.  sent after a create key or create value.
this might be some sort of "sync" or "refresh" command, sent after
modification of the registry...
****************************************************************************/
WERROR cli_reg_flush_key(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                           POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_FLUSH_KEY q_o;
	REG_R_FLUSH_KEY r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf , MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_flush_key(&q_o, hnd);

	if (!reg_io_q_flush_key("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_FLUSH_KEY, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (reg_io_r_flush_key("", &r_o, &rbuf, 0))
		result = r_o.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Query Key
****************************************************************************/
WERROR cli_reg_query_key(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                           POLICY_HND *hnd,
                           char *key_class, uint32 *class_len,
                           uint32 *num_subkeys, uint32 *max_subkeylen,
                           uint32 *max_classlen, uint32 *num_values,
                           uint32 *max_valnamelen, uint32 *max_valbufsize,
                           uint32 *sec_desc, NTTIME *mod_time)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_QUERY_KEY q_o;
	REG_R_QUERY_KEY r_o;
	uint32 saved_class_len = *class_len;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf , MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_query_key( &q_o, hnd, key_class );

	if (!reg_io_q_query_key("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_QUERY_KEY, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (!reg_io_r_query_key("", &r_o, &rbuf, 0))
		goto done;

	result = r_o.status;
	if (NT_STATUS_EQUAL(result, ERROR_INSUFFICIENT_BUFFER)) {
		*class_len = r_o.class.string->uni_max_len;
		goto done;
	} else if (!NT_STATUS_IS_OK(result))
		goto done;

	*class_len      = r_o.class.string->uni_max_len;
	unistr2_to_ascii(key_class, r_o.class.string, saved_class_len-1);
	*num_subkeys    = r_o.num_subkeys   ;
	*max_subkeylen  = r_o.max_subkeylen ;
	*num_values     = r_o.num_values    ;
	*max_valnamelen = r_o.max_valnamelen;
	*max_valbufsize = r_o.max_valbufsize;
	*sec_desc       = r_o.sec_desc      ;
	*mod_time       = r_o.mod_time      ;
	/* Maybe: *max_classlen = r_o.reserved; */

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Unknown 1A
****************************************************************************/
WERROR cli_reg_getversion(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                            POLICY_HND *hnd, uint32 *unk)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_GETVERSION q_o;
	REG_R_GETVERSION r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf , MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_getversion(&q_o, hnd);

	if (!reg_io_q_getversion("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_GETVERSION, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (!reg_io_r_getversion("", &r_o, &rbuf, 0))
		goto done;

	result = r_o.status;
	if (NT_STATUS_IS_OK(result))
		if (unk != NULL)
			*unk = r_o.unknown;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Query Info
****************************************************************************/
WERROR cli_reg_query_info(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                           POLICY_HND *hnd, const char *val_name,
                           uint32 *type, REGVAL_BUFFER *buffer)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_INFO q_o;
	REG_R_INFO r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_info(&q_o, hnd, val_name, buffer);

	if (!reg_io_q_info("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_INFO, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (!reg_io_r_info("", &r_o, &rbuf, 0))
		goto done;

	result = r_o.status;
	if (NT_STATUS_IS_OK(result)) {
		*type = *r_o.type;
		*buffer = *r_o.value;
	}

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Set Key Security 
****************************************************************************/
WERROR cli_reg_set_key_sec(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                             POLICY_HND *hnd, uint32 sec_info,
                             size_t secdesc_size, SEC_DESC *sec_desc)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_SET_KEY_SEC q_o;
	REG_R_SET_KEY_SEC r_o;
	SEC_DESC_BUF *sec_desc_buf;
	WERROR result = WERR_GENERAL_FAILURE;

	/*
	 * Flatten the security descriptor.
	 */
	sec_desc_buf = make_sec_desc_buf(mem_ctx, secdesc_size, sec_desc);
	if (sec_desc_buf == NULL)
		goto done;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_set_key_sec(&q_o, hnd, sec_info, sec_desc_buf);

	if (!reg_io_q_set_key_sec("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_SET_KEY_SEC, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (reg_io_r_set_key_sec("", &r_o, &rbuf, 0))
		result = r_o.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}


/****************************************************************************
do a REG Query Key Security 
****************************************************************************/
WERROR cli_reg_get_key_sec(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                             POLICY_HND *hnd, uint32 sec_info,
                             uint32 *sec_buf_size, SEC_DESC_BUF *sec_buf)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_GET_KEY_SEC q_o;
	REG_R_GET_KEY_SEC r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_get_key_sec(&q_o, hnd, sec_info, *sec_buf_size, sec_buf);

	if (!reg_io_q_get_key_sec("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_GET_KEY_SEC, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	r_o.data = sec_buf;

	if (*sec_buf_size != 0)
	{
		sec_buf->sec = (SEC_DESC*)talloc(mem_ctx, *sec_buf_size);
	}

	if (!reg_io_r_get_key_sec("", &r_o, &rbuf, 0))
		goto done;

	result = r_o.status;
	if (NT_STATUS_IS_OK(result))
		(*sec_buf_size) = r_o.data->len;
	else if (NT_STATUS_EQUAL(result, ERROR_INSUFFICIENT_BUFFER)) 
	{
		/*
		 * get the maximum buffer size: it was too small
		 */
		(*sec_buf_size) = r_o.hdr_sec.buf_max_len;
	}

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Delete Value
****************************************************************************/
WERROR cli_reg_delete_val(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                            POLICY_HND *hnd, char *val_name)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_DELETE_VALUE q_o;
	REG_R_DELETE_VALUE r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_delete_val(&q_o, hnd, val_name);

	if (!reg_io_q_delete_val("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_DELETE_VALUE, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (reg_io_r_delete_val("", &r_o, &rbuf, 0))
		result = r_o.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Delete Key
****************************************************************************/
WERROR cli_reg_delete_key(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                            POLICY_HND *hnd, char *key_name)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_DELETE_KEY q_o;
	REG_R_DELETE_KEY r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_delete_key(&q_o, hnd, key_name);

	if (!reg_io_q_delete_key("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_DELETE_KEY, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (reg_io_r_delete_key("", &r_o, &rbuf, 0))
		result = r_o.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Create Key
****************************************************************************/
WERROR cli_reg_create_key(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                            POLICY_HND *hnd, char *key_name, char *key_class,
                            uint32 access_desired, POLICY_HND *key)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_CREATE_KEY q_o;
	REG_R_CREATE_KEY r_o;
	SEC_DESC *sec;
	SEC_DESC_BUF *sec_buf;
	size_t sec_len;
	WERROR result = WERR_GENERAL_FAILURE;

	ZERO_STRUCT(q_o);

	if ((sec = make_sec_desc(mem_ctx, 1, SEC_DESC_SELF_RELATIVE,
	                         NULL, NULL, NULL, NULL, &sec_len)) == NULL)
		goto done;

	if ((sec_buf = make_sec_desc_buf(mem_ctx, sec_len, sec)) == NULL)
		goto done;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_create_key(&q_o, hnd, key_name, key_class, access_desired, sec_buf);

	if (!reg_io_q_create_key("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_CREATE_KEY, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (!reg_io_r_create_key("", &r_o, &rbuf, 0))
		goto done;

	result = r_o.status;
	if (NT_STATUS_IS_OK(result))
		*key = r_o.key_pol;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Enum Key
****************************************************************************/
WERROR cli_reg_enum_key(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                          POLICY_HND *hnd, int key_index, fstring key_name,
                          uint32 *unk_1, uint32 *unk_2, time_t *mod_time)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_ENUM_KEY q_o;
	REG_R_ENUM_KEY r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_enum_key(&q_o, hnd, key_index);

	if (!reg_io_q_enum_key("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_ENUM_KEY, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (!reg_io_r_enum_key("", &r_o, &rbuf, 0))
		goto done;

	result = r_o.status;
	if (NT_STATUS_IS_OK(result)) {
		(*unk_1) = r_o.unknown_1;
		(*unk_2) = r_o.unknown_2;
		unistr3_to_ascii(key_name, &r_o.key_name,
		                sizeof(fstring)-1);
		(*mod_time) = nt_time_to_unix(&r_o.time);
	}

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Create Value
****************************************************************************/
WERROR cli_reg_create_val(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                            POLICY_HND *hnd, char *val_name, uint32 type,
                            BUFFER3 *data)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_CREATE_VALUE q_o;
	REG_R_CREATE_VALUE r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_create_val(&q_o, hnd, val_name, type, data);

	if (!reg_io_q_create_val("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_CREATE_VALUE, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshal response */

	if (reg_io_r_create_val("", &r_o, &rbuf, 0))
		result = r_o.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Enum Value
****************************************************************************/
WERROR cli_reg_enum_val(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                          POLICY_HND *hnd, int val_index, int max_valnamelen,
                          int max_valbufsize, fstring val_name,
                          uint32 *val_type, REGVAL_BUFFER *value)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_ENUM_VALUE q_o;
	REG_R_ENUM_VALUE r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_enum_val(&q_o, hnd, val_index, val_name, max_valbufsize);

	if (!reg_io_q_enum_val("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_ENUM_VALUE, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarshall response */

	if (!reg_io_r_enum_val("", &r_o, &rbuf, 0))
		goto done;

	result = r_o.status;
	if (NT_STATUS_IS_OK(result) ||
	    NT_STATUS_EQUAL(result, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		(*val_type) = *r_o.type;
		unistr2_to_ascii(val_name, r_o.name.string, sizeof(fstring)-1);
		*value = *r_o.value;
	}

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Open Key
****************************************************************************/
WERROR cli_reg_open_entry(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                            POLICY_HND *hnd, char *key_name,
                            uint32 access_desired, POLICY_HND *key_hnd)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_OPEN_ENTRY q_o;
	REG_R_OPEN_ENTRY r_o;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_open_entry(&q_o, hnd, key_name, access_desired);

	/* turn parameters into data stream */
	if (!reg_io_q_open_entry("", &q_o, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_OPEN_ENTRY, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_o);

	/* Unmarsall response */

	if (!reg_io_r_open_entry("", &r_o, &rbuf, 0))
		goto done;

	result = r_o.status;
	if (NT_STATUS_IS_OK(result))
		*key_hnd = r_o.pol;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}

/****************************************************************************
do a REG Close
****************************************************************************/
WERROR cli_reg_close(struct cli_state *cli, TALLOC_CTX *mem_ctx,
                       POLICY_HND *hnd)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	REG_Q_CLOSE q_c;
	REG_R_CLOSE r_c;
	WERROR result = WERR_GENERAL_FAILURE;

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_reg_q_close(&q_c, hnd);

	if (!reg_io_q_close("", &q_c, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_WINREG, REG_CLOSE, &qbuf, &rbuf))
		goto done;

	ZERO_STRUCT(r_c);

	/* Unmarshall response */

	if (reg_io_r_close("", &r_c, &rbuf, 0))
		result = r_c.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}


