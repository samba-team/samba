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
	fstring type;
	uint32 unk_0;
	uint32 unk_1;
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	int i;

	POLICY_HND key_pol;
	fstring key_name;

	/*
	 * query key info
	 */

	uint32 unknown_0; 
	uint32 unknown_1;
	uint32 num_subkeys;
	uint32 max_subkeylen;
	uint32 unknown_4; 
	uint32 num_values;
	uint32 max_valnamelen;
	uint32 max_valbufsize;
	uint32 unknown_8;
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

	/* query it */
	res1 = res1 ? do_reg_query_info(smb_cli, &key_pol,
	                        type, &unk_0, &unk_1) : False;

	res1 = res1 ? do_reg_query_unk_10(smb_cli,
				&key_pol,
	                        &unknown_0, &unknown_1,
	                        &num_subkeys, &max_subkeylen,
	                        &unknown_4, &num_values,
	                        &max_valnamelen, &max_valbufsize,
	                        &unknown_8, &mod_time) : False;

	if (res1)
	{
		fprintf(out_hnd,"Registry Query Info Key\n");
		fprintf(out_hnd,"unk_0,1 : 0x%x 0x%x\n", unknown_0, unknown_1);
		fprintf(out_hnd,"subkeys, max_len: %d %d\n", num_subkeys, max_subkeylen);
		fprintf(out_hnd,"unk_4 : 0x%x\n", unknown_4);
		fprintf(out_hnd,"vals, max_len, max_size: 0x%x 0x%x 0x%x\n", num_values, max_valnamelen, max_valbufsize);
		fprintf(out_hnd,"unk_8: 0x%x\n", unknown_8);
		fprintf(out_hnd,"mod time: %s\n", http_timestring(nt_time_to_unix(&mod_time)));
	}

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
		fprintf(out_hnd,"Registry Enumeration\n");
		fprintf(out_hnd,"Type: %s unk_0:%x unk_1:%x\n", type, unk_0, unk_1);
	}
	else
	{
		DEBUG(5,("cmd_reg_enum: query failed\n"));
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
	int i;

	/*
	 * query key info
	 */

	uint32 unknown_0; 
	uint32 unknown_1;
	uint32 num_subkeys;
	uint32 max_subkeylen;
	uint32 unknown_4; 
	uint32 num_values;
	uint32 max_valnamelen;
	uint32 unknown_7;
	uint32 unknown_8;
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

	res2 = res1 ? do_reg_query_unk_10(smb_cli,
				&info->dom.reg_pol_connect,
	                        &unknown_0, &unknown_1,
	                        &num_subkeys, &max_subkeylen,
	                        &unknown_4, &num_values,
	                        &max_valnamelen, &unknown_7,
	                        &unknown_8, &mod_time) : False;

	if (res2)
	{
		fprintf(out_hnd,"Registry Query Info Key\n");
		fprintf(out_hnd,"unk_0,1 : 0x%x 0x%x\n", unknown_0, unknown_1);
		fprintf(out_hnd,"subkeys, max_len: %d %d\n", num_subkeys, max_subkeylen);
		fprintf(out_hnd,"unk_4 : 0x%x\n", unknown_4);
		fprintf(out_hnd,"vals, max_len : 0x%x 0x%x\n", num_values, max_valnamelen);
		fprintf(out_hnd,"unk_7, 8: 0x%x 0x%x\n", unknown_7, unknown_8);
		fprintf(out_hnd,"mod time: %s\n", http_timestring(nt_time_to_unix(&mod_time)));
	}

	for (i = 0; i < num_subkeys; i++)
	{
		/* unknown 1a it */
		res2 = res1 ? do_reg_unknown_1a(smb_cli, &info->dom.reg_pol_connect,
					&unk_1a_response) : False;

		if (res2)
		{
			fprintf(out_hnd,"Unknown 1a response: %x\n", unk_1a_response);
		}

		/* enum key */
		res2 = res2 ? do_reg_enum_key(smb_cli, &info->dom.reg_pol_connect,
					i, enum_name,
					&enum_unk1, &enum_unk2,
					&key_mod_time) : False;
		
		if (res2)
		{
			fprintf(out_hnd,"Enum Key: %s  ", enum_name);
			fprintf(out_hnd,"unk (%08x %08x)  ", enum_unk1, enum_unk2);
			fprintf(out_hnd,"mod time: %s\n", http_timestring(key_mod_time));
		}
	}

	/* close the handles */
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

