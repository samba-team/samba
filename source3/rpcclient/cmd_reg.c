/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   
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



#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

extern struct cli_state *smb_cli;
extern int smb_tidx;

extern FILE* out_hnd;


/****************************************************************************
nt registry enum
****************************************************************************/
void cmd_reg_enum(struct client_info *info)
{
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	int i;

	POLICY_HND key_pol;
	fstring key_name;

	/*
	 * query key info
	 */

	fstring key_class;
	uint32 max_class_len = 0;
	uint32 num_subkeys;
	uint32 max_subkeylen;
	uint32 max_subkeysize; 
	uint32 num_values;
	uint32 max_valnamelen;
	uint32 max_valbufsize;
	uint32 sec_desc;
	NTTIME mod_time;

	/*
	 * unknown 0x1a request
	 */

	uint32 unk_1a_response;

	DEBUG(5, ("cmd_reg_enum: smb_cli->fd:%d\n", smb_cli->fd));

	if (!next_token(NULL, key_name, NULL, sizeof(key_name)))
	{
		fprintf(out_hnd, "regenum key_name\n");
		return;
	}

	/* open WINREG session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_WINREG) : False;

	/* open registry receive a policy handle */
	res = res ? do_reg_open_policy(smb_cli,
				0x84E0, 0x02000000,
				&info->dom.reg_pol_connect) : False;

	/* open an entry */
	res1 = res  ? do_reg_open_entry(smb_cli, &info->dom.reg_pol_connect,
	                         key_name, 0x02000000, &key_pol) : False;

	res1 = res1 ? do_reg_query_key(smb_cli,
				&key_pol,
				key_class, &max_class_len,
	                        &num_subkeys, &max_subkeylen, &max_subkeysize,
				&num_values, &max_valnamelen, &max_valbufsize,
	                        &sec_desc, &mod_time) : False;

	for (i = 0; i < num_subkeys; i++)
	{
		/*
		 * enumerate key
		 */

		fstring enum_name;
		uint32 enum_unk1;
		uint32 enum_unk2;
		time_t key_mod_time;

		/* unknown 1a it */
		res2 = res1 ? do_reg_unknown_1a(smb_cli, &key_pol,
					&unk_1a_response) : False;

		if (res2 && unk_1a_response != 5)
		{
			fprintf(out_hnd,"Unknown 1a response: %x\n", unk_1a_response);
		}

		/* enum key */
		res2 = res2 ? do_reg_enum_key(smb_cli, &key_pol,
					i, enum_name,
					&enum_unk1, &enum_unk2,
					&key_mod_time) : False;
		
		if (res2)
		{
			display_reg_key_info(out_hnd, ACTION_HEADER   , enum_name, key_mod_time);
			display_reg_key_info(out_hnd, ACTION_ENUMERATE, enum_name, key_mod_time);
			display_reg_key_info(out_hnd, ACTION_FOOTER   , enum_name, key_mod_time);
		}

	}

	for (i = 0; i < num_values; i++)
	{
		/*
		 * enumerate key
		 */

		uint32 val_type;
		BUFFER2 value;
		fstring val_name;

		/* unknown 1a it */
		res2 = res1 ? do_reg_unknown_1a(smb_cli, &key_pol,
					&unk_1a_response) : False;

		if (res2 && unk_1a_response != 5)
		{
			fprintf(out_hnd,"Unknown 1a response: %x\n", unk_1a_response);
		}

		/* enum key */
		res2 = res2 ? do_reg_enum_val(smb_cli, &key_pol,
					i, max_valnamelen, max_valbufsize,
		                        val_name, &val_type, &value) : False;
		
		if (res2)
		{
			display_reg_value_info(out_hnd, ACTION_HEADER   , val_name, val_type, &value);
			display_reg_value_info(out_hnd, ACTION_ENUMERATE, val_name, val_type, &value);
			display_reg_value_info(out_hnd, ACTION_FOOTER   , val_name, val_type, &value);
		}
	}

	/* close the handles */
	res1 = res1 ? do_reg_close(smb_cli, &key_pol) : False;
	res  = res  ? do_reg_close(smb_cli, &info->dom.reg_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli);

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_reg_enum: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_reg_enum: query failed\n"));
	}
}

/****************************************************************************
nt registry query key
****************************************************************************/
void cmd_reg_query_key(struct client_info *info)
{
	BOOL res = True;
	BOOL res1 = True;

	POLICY_HND key_pol;
	fstring key_name;

	/*
	 * query key info
	 */

	fstring key_class;
	uint32 key_class_len = 0;
	uint32 num_subkeys;
	uint32 max_subkeylen;
	uint32 max_subkeysize; 
	uint32 num_values;
	uint32 max_valnamelen;
	uint32 max_valbufsize;
	uint32 sec_desc;
	NTTIME mod_time;

	DEBUG(5, ("cmd_reg_enum: smb_cli->fd:%d\n", smb_cli->fd));

	if (!next_token(NULL, key_name, NULL, sizeof(key_name)))
	{
		fprintf(out_hnd, "regquery key_name\n");
		return;
	}

	/* open WINREG session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_WINREG) : False;

	/* open registry receive a policy handle */
	res = res ? do_reg_open_policy(smb_cli,
				0x84E0, 0x02000000,
				&info->dom.reg_pol_connect) : False;

	/* open an entry */
	res1 = res  ? do_reg_open_entry(smb_cli, &info->dom.reg_pol_connect,
	                         key_name, 0x02000000, &key_pol) : False;

	res1 = res1 ? do_reg_query_key(smb_cli,
				&key_pol,
				key_class, &key_class_len,
	                        &num_subkeys, &max_subkeylen, &max_subkeysize,
				&num_values, &max_valnamelen, &max_valbufsize,
	                        &sec_desc, &mod_time) : False;

	if (res1 && key_class_len != 0)
	{
		res1 = res1 ? do_reg_query_key(smb_cli,
				&key_pol,
				key_class, &key_class_len,
	                        &num_subkeys, &max_subkeylen, &max_subkeysize,
				&num_values, &max_valnamelen, &max_valbufsize,
	                        &sec_desc, &mod_time) : False;
	}

	if (res1)
	{
		fprintf(out_hnd,"Registry Query Info Key\n");
		fprintf(out_hnd,"key class: %s\n", key_class);
		fprintf(out_hnd,"subkeys, max_len, max_size: %d %d %d\n", num_subkeys, max_subkeylen, max_subkeysize);
		fprintf(out_hnd,"vals, max_len, max_size: 0x%x 0x%x 0x%x\n", num_values, max_valnamelen, max_valbufsize);
		fprintf(out_hnd,"sec desc: 0x%x\n", sec_desc);
		fprintf(out_hnd,"mod time: %s\n", http_timestring(nt_time_to_unix(&mod_time)));
	}

	/* close the handles */
	res1 = res1 ? do_reg_close(smb_cli, &key_pol) : False;
	res  = res  ? do_reg_close(smb_cli, &info->dom.reg_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli);

	if (res && res1)
	{
		DEBUG(5,("cmd_reg_query: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_reg_query: query failed\n"));
	}
}

/****************************************************************************
nt registry test
****************************************************************************/
void cmd_reg_test2(struct client_info *info)
{
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	BOOL res3 = True;
	int i;

	/*
	 * query key info
	 */

	POLICY_HND key_pol;
	fstring key_class;
	uint32 max_class_len;
	uint32 num_subkeys;
	uint32 max_subkeylen;
	uint32 max_subkeysize; 
	uint32 num_values;
	uint32 max_valnamelen;
	uint32 max_valbufsize;
	uint32 sec_desc;
	NTTIME mod_time;

	/*
	 * unknown 0x1a request
	 */

	uint32 unk_1a_response;

	/*
	 * enumerate key
	 */

	fstring enum_name;
	uint32 enum_unk1;
	uint32 enum_unk2;
	time_t key_mod_time;

	DEBUG(5, ("cmd_reg_test: smb_cli->fd:%d\n", smb_cli->fd));

	/* open WINREG session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_WINREG) : False;

	/* open registry receive a policy handle */
	res  = res ? do_reg_open_policy(smb_cli,
				0x84E0, 0x02000000,
				&info->dom.reg_pol_connect) : False;

	res1 = res ? do_reg_open_unk_4(smb_cli,
				0x84E0, 0x02000000,
				&info->dom.reg_pol_unk_4  ) : False;

	res2 = res1 ? do_reg_query_key(smb_cli,
				&key_pol,
				key_class, &max_class_len,
	                        &num_subkeys, &max_subkeylen, &max_subkeysize,
				&num_values, &max_valnamelen, &max_valbufsize,
	                        &sec_desc, &mod_time) : False;

	for (i = 0; i < num_subkeys; i++)
	{
		/* unknown 1a it */
		res3 = res2 ? do_reg_unknown_1a(smb_cli, &info->dom.reg_pol_connect,
					&unk_1a_response) : False;

		if (res3)
		{
			fprintf(out_hnd,"Unknown 1a response: %x\n", unk_1a_response);
		}

		/* enum key */
		res3 = res3 ? do_reg_enum_key(smb_cli, &info->dom.reg_pol_connect,
					i, enum_name,
					&enum_unk1, &enum_unk2,
					&key_mod_time) : False;
		
		if (res3)
		{
			fprintf(out_hnd,"Enum Key: %s  ", enum_name);
			fprintf(out_hnd,"unk (%08x %08x)  ", enum_unk1, enum_unk2);
			fprintf(out_hnd,"mod time: %s\n", http_timestring(key_mod_time));
		}
	}

	/* close the handles */
	res2 = res2 ? do_reg_close(smb_cli, &key_pol                  ) : False;
	res1 = res1 ? do_reg_close(smb_cli, &info->dom.reg_pol_unk_4  ) : False;
	res  = res  ? do_reg_close(smb_cli, &info->dom.reg_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli);

	if (res && res1 && res2)
	{
		DEBUG(5,("cmd_reg_test2: query succeeded\n"));
		fprintf(out_hnd,"Registry Test2\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_test2: query failed\n"));
	}
}

/****************************************************************************
nt registry create value
****************************************************************************/
void cmd_reg_create_val(struct client_info *info)
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND parent_pol;
	fstring parent_name;
	fstring val_name;
	fstring tmp;
	uint32 val_type;
	BUFFER3 value;

#if 0
	uint32 unk_0;
	uint32 unk_1;
	/* query it */
	res1 = res1 ? do_reg_query_info(smb_cli, &val_pol,
	                        type, &unk_0, &unk_1) : False;
#endif

	DEBUG(5, ("cmd_reg_get_val_sec: smb_cli->fd:%d\n", smb_cli->fd));

	if (!next_token(NULL, parent_name, NULL, sizeof(parent_name)))
	{
		fprintf(out_hnd, "regcreate <parent val name> <val_name> <val_type> <val>\n");
		return;
	}

	if (!next_token(NULL, val_name   , NULL, sizeof(val_name   )))
	{
		fprintf(out_hnd, "regcreate <parent val name> <val_name> <val_type> <val>\n");
		return;
	}

	if (!next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		fprintf(out_hnd, "regcreate <parent val name> <val_name> <val_type (1|4)> <val>\n");
		return;
	}

	val_type = atoi(tmp);

	if (val_type != 1 && val_type != 3 && val_type != 4)
	{
		fprintf(out_hnd, "val_type 1=UNISTR, 3=BYTES, 4=DWORD supported\n");
		return;
	}

	if (!next_token(NULL, tmp, NULL, sizeof(tmp)))
	{
		fprintf(out_hnd, "regcreate <parent val name> <val_name> <val_type (1|4)> <val>\n");
		return;
	}

	switch (val_type)
	{
		case 0x01: /* UNISTR */
		{
			make_buffer3_str(&value, tmp, strlen(tmp)+1);
			break;
		}
		case 0x03: /* BYTES */
		{
			make_buffer3_hex(&value, tmp);
			break;
		}
		case 0x04: /* DWORD */
		{
			uint32 tmp_val;
			if (strnequal(tmp, "0x", 2))
			{
				tmp_val = strtol(tmp, (char**)NULL, 16);
			}
			else
			{
				tmp_val = strtol(tmp, (char**)NULL, 10);
			}
			make_buffer3_uint32(&value, tmp_val);
			break;
		}
		default:
		{
			fprintf(out_hnd, "i told you i only deal with UNISTR, DWORD and BYTES!\n");
			return;
		}
	}
		
	DEBUG(10,("key data:\n"));
	dump_data(10, (char *)value.buffer, value.buf_len);

	/* open WINREG session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_WINREG) : False;

	/* open registry receive a policy handle */
	res  = res ? do_reg_open_policy(smb_cli,
				0x84E0, 0x02000000,
				&info->dom.reg_pol_connect) : False;

	/* open an entry */
	res3 = res ? do_reg_open_entry(smb_cli, &info->dom.reg_pol_connect,
				 parent_name, 0x02000000, &parent_pol) : False;

	/* create an entry */
	res4 = res3 ? do_reg_create_val(smb_cli, &parent_pol,
				 val_name, val_type, &value) : False;

	/* some sort of "sync" or "refresh" on the parent key? */
	res4 = res4 ? do_reg_unk_b(smb_cli, &parent_pol) : False;

	/* close the val handle */
	res3 = res3 ? do_reg_close(smb_cli, &parent_pol) : False;

	/* close the registry handles */
	res  = res  ? do_reg_close(smb_cli, &info->dom.reg_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli);

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_create_val: query succeeded\n"));
		fprintf(out_hnd,"OK\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_create_val: query failed\n"));
	}
}

/****************************************************************************
nt registry delete key
****************************************************************************/
void cmd_reg_delete_key(struct client_info *info)
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND parent_pol;
	fstring parent_name;
	fstring key_name;

	DEBUG(5, ("cmd_reg_delete_key: smb_cli->fd:%d\n", smb_cli->fd));

	if (!next_token(NULL, parent_name, NULL, sizeof(parent_name)))
	{
		fprintf(out_hnd, "regcreate <parent key name> <key_name>\n");
		return;
	}

	if (!next_token(NULL, key_name   , NULL, sizeof(key_name   )))
	{
		fprintf(out_hnd, "regcreate <parent key name> <key_name>\n");
		return;
	}

	/* open WINREG session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_WINREG) : False;

	/* open registry receive a policy handle */
	res  = res ? do_reg_open_policy(smb_cli,
				0x84E0, 0x02000000,
				&info->dom.reg_pol_connect) : False;

	/* open an entry */
	res3 = res ? do_reg_open_entry(smb_cli, &info->dom.reg_pol_connect,
				 parent_name, 0x02000000, &parent_pol) : False;

	/* create an entry */
	res4 = res3 ? do_reg_delete_key(smb_cli, &parent_pol, key_name) : False;

	/* some sort of "sync" or "refresh" on the parent key? */
	res4 = res4 ? do_reg_unk_b(smb_cli, &parent_pol) : False;

	/* close the key handle */
	res3 = res3 ? do_reg_close(smb_cli, &parent_pol) : False;

	/* close the registry handles */
	res  = res  ? do_reg_close(smb_cli, &info->dom.reg_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli);

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_delete_key: query succeeded\n"));
		fprintf(out_hnd,"OK\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_delete_key: query failed\n"));
	}
}

/****************************************************************************
nt registry create key
****************************************************************************/
void cmd_reg_create_key(struct client_info *info)
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND parent_pol;
	POLICY_HND key_pol;
	fstring parent_name;
	fstring key_name;
	fstring key_class;
	SEC_INFO sam_access;

#if 0
	uint32 unk_0;
	uint32 unk_1;
	/* query it */
	res1 = res1 ? do_reg_query_info(smb_cli, &key_pol,
	                        type, &unk_0, &unk_1) : False;
#endif

	DEBUG(5, ("cmd_reg_create_key: smb_cli->fd:%d\n", smb_cli->fd));

	if (!next_token(NULL, parent_name, NULL, sizeof(parent_name)))
	{
		fprintf(out_hnd, "regcreate <parent key name> <key_name> [key_class]\n");
		return;
	}

	if (!next_token(NULL, key_name   , NULL, sizeof(key_name   )))
	{
		fprintf(out_hnd, "regcreate <parent key name> <key_name> [key_class]\n");
		return;
	}

	if (!next_token(NULL, key_class, NULL, sizeof(key_class)))
	{
		memset(key_class, 0, sizeof(key_class));
	}

	/* set access permissions */
	sam_access.perms = SEC_RIGHTS_READ;

	/* open WINREG session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_WINREG) : False;

	/* open registry receive a policy handle */
	res  = res ? do_reg_open_policy(smb_cli,
				0x84E0, 0x02000000,
				&info->dom.reg_pol_connect) : False;

	/* open an entry */
	res3 = res ? do_reg_open_entry(smb_cli, &info->dom.reg_pol_connect,
				 parent_name, 0x02000000, &parent_pol) : False;

	/* create an entry */
	res4 = res3 ? do_reg_create_key(smb_cli, &parent_pol,
				 key_name, key_class, &sam_access, &key_pol) : False;

	/* some sort of "sync" or "refresh" on the parent key? */
	res4 = res4 ? do_reg_unk_b(smb_cli, &parent_pol) : False;

	/* close the key handle */
	res4 = res4 ? do_reg_close(smb_cli, &key_pol) : False;

	/* close the key handle */
	res3 = res3 ? do_reg_close(smb_cli, &parent_pol) : False;

	/* close the registry handles */
	res  = res  ? do_reg_close(smb_cli, &info->dom.reg_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli);

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_create_key: query succeeded\n"));
		fprintf(out_hnd,"OK\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_create_key: query failed\n"));
	}
}

/****************************************************************************
nt registry security info
****************************************************************************/
void cmd_reg_get_key_sec(struct client_info *info)
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND key_pol;
	fstring key_name;

	/*
	 * security info
	 */

	uint32 sec_buf_size;
	SEC_DESC_BUF sec_buf;

	DEBUG(5, ("cmd_reg_get_key_sec: smb_cli->fd:%d\n", smb_cli->fd));

	if (!next_token(NULL, key_name, NULL, sizeof(key_name)))
	{
		fprintf(out_hnd, "regtest key_name\n");
		return;
	}

	/* open WINREG session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_WINREG) : False;

	/* open registry receive a policy handle */
	res  = res ? do_reg_open_policy(smb_cli,
				0x84E0, 0x02000000,
				&info->dom.reg_pol_connect) : False;

	/* open an entry */
	res3 = res ? do_reg_open_entry(smb_cli, &info->dom.reg_pol_connect,
				 key_name, 0x02000000, &key_pol) : False;

	/* query key sec info.  first call sets sec_buf_size. */
	sec_buf_size = 0;
	res4 = res3 ? do_reg_get_key_sec(smb_cli, &key_pol,
				&sec_buf_size, &sec_buf) : False;
	
	res4 = res4 ? do_reg_get_key_sec(smb_cli, &key_pol,
				&sec_buf_size, &sec_buf) : False;

	if (res4 && sec_buf.len > 0)
	{
		fprintf(out_hnd, "Security Info for %s: (%d)\n",
				 key_name, sec_buf_size);
		display_sec_desc(out_hnd, ACTION_HEADER   , &sec_buf.sec);
		display_sec_desc(out_hnd, ACTION_ENUMERATE, &sec_buf.sec);
		display_sec_desc(out_hnd, ACTION_FOOTER   , &sec_buf.sec);
	}

	/* close the key handle */
	res3 = res3 ? do_reg_close(smb_cli, &key_pol) : False;

	/* close the registry handles */
	res  = res  ? do_reg_close(smb_cli, &info->dom.reg_pol_connect) : False;

	/* close the session */
	cli_nt_session_close(smb_cli);

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_test2: query succeeded\n"));
		fprintf(out_hnd,"Registry Test2\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_test2: query failed\n"));
	}
}

