/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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
#include "rpc_parse.h"
#include "rpc_client.h"
#include "rpcclient.h"

extern int DEBUGLEVEL;

extern FILE* out_hnd;

/*
 * keys.  of the form:
 * ----
 *
 * [HKLM]|[HKU]|[HKCR]\[parent_keyname]\[subkey]|[value]
 *
 * reg_getsubkey() splits this down into:
 * [HKLM]|[HKU]|[HKCR]\[parent_keyname_components] and [subkey]|[value]
 *
 * reg_connect() splits the left side down further into:
 * [HKLM]|[HKU]|[HKCR] and [parent_keyname_components].
 *
 * HKLM is short for HKEY_LOCAL_MACHINE
 * HKCR is short for HKEY_CLASSES_ROOT
 * HKU  is short for HKEY_USERS
 *
 * oh, and HKEY stands for "Hive Key".
 *
 */

static void reg_display_key(int val, const char *full_keyname, int num)
{
	switch (val)
	{
		case 0:
		{
			/* initialsation */
			report(out_hnd, "Key Name:\t%s\n", full_keyname);
			break;
		}
		case 1:
		{
			/* subkeys initialisation */
			if (num > 0)
			{
				report(out_hnd,"Subkeys\n");
				report(out_hnd,"-------\n");
			}
			break;
		}
		case 2:
		{
			/* values initialisation */
			if (num > 0)
			{
				report(out_hnd,"Key Values\n");
				report(out_hnd,"----------\n");
			}
			break;
		}
		case 3:
		{
			/* clean-up */
			break;
		}
		default:
		{
			break;
		}
	}
}

void split_server_keyname(char *srv_name, char *key, const char* arg)
{
	pstrcpy(key, arg);

	if (strnequal("\\\\", key, 2))
	{
		char *p = strchr(&key[2], '\\');
		if (p == NULL)
		{
			key[0] = 0;
			return;
		}

		*p = 0;

		fstrcpy(srv_name, key);
		pstrcpy(key, &arg[strlen(srv_name)+1]);
	}
}

/****************************************************************************
nt registry enum
****************************************************************************/
BOOL msrpc_reg_enum_key(const char* srv_name, const char* full_keyname,
				REG_FN(reg_fn),
				REG_KEY_FN(reg_key_fn),
				REG_VAL_FN(reg_val_fn))
{
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;
	int i;

	POLICY_HND key_pol;
	POLICY_HND pol_con;
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

	DEBUG(5, ("reg_enum_key: %s\n", full_keyname));

	/* open registry receive a policy handle */
	res = res ? reg_connect(srv_name, full_keyname, key_name, 
                                SEC_RIGHTS_MAXIMUM_ALLOWED, &pol_con) : False;

	if ((*key_name) != 0)
	{
		/* open an entry */
		res1 = res  ? reg_open_entry(&pol_con, key_name, 
                                             SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                             &key_pol) : False;
	}
	else
	{
		memcpy(&key_pol, &pol_con, sizeof(key_pol));
	}

	res1 = res1 ? reg_query_key(&key_pol,
				key_class, &max_class_len,
	                        &num_subkeys, &max_subkeylen, &max_subkeysize,
				&num_values, &max_valnamelen, &max_valbufsize,
	                        &sec_desc, &mod_time) : False;

	if (res1 && reg_fn != NULL)
	{
		reg_fn(0, full_keyname, 0);
		reg_fn(1, full_keyname, num_subkeys);
	}

	for (i = 0; i < num_subkeys && reg_key_fn != NULL; i++)
	{
		/*
		 * enumerate key
		 */

		fstring enum_name;
		uint32 enum_unk1;
		uint32 enum_unk2;
		time_t key_mod_time;

		/* unknown 1a it */
		res2 = res1 ? reg_unknown_1a(&key_pol,
					&unk_1a_response) : False;

		if (res2 && unk_1a_response != 5)
		{
			report(out_hnd,"Unknown 1a response: %x\n", unk_1a_response);
		}

		/* enum key */
		res2 = res2 ? reg_enum_key(&key_pol,
					i, enum_name,
					&enum_unk1, &enum_unk2,
					&key_mod_time) : False;
		
		if (res2)
		{
			reg_key_fn(full_keyname, enum_name, key_mod_time);
		}

	}

	if (reg_fn != NULL)
	{
		reg_fn(2, full_keyname, num_values);
	}

	for (i = 0; i < num_values && reg_val_fn != NULL; i++)
	{
		/*
		 * enumerate key
		 */

		uint32 val_type;
		BUFFER2 value;
		fstring val_name;

		/* unknown 1a it */
		res2 = res1 ? reg_unknown_1a(&key_pol,
					&unk_1a_response) : False;

		if (res2 && unk_1a_response != 5)
		{
			report(out_hnd,"Unknown 1a response: %x\n", unk_1a_response);
		}

		/* enum key */
		res2 = res2 ? reg_enum_val(&key_pol,
					i, max_valnamelen, max_valbufsize,
		                        val_name, &val_type, &value) : False;
		
		if (res2)
		{
			reg_val_fn(full_keyname, val_name, val_type, &value);
		}
	}

	if (res1 && reg_fn != NULL)
	{
		reg_fn(3, full_keyname, 0);
	}

	/* close the handles */
	if ((*key_name) != 0)
	{
		res1 = res1 ? reg_close(&key_pol) : False;
	}
	res  = res  ? reg_close(&pol_con) : False;

	if (res && res1 && res2)
	{
		DEBUG(5,("msrpc_reg_enum_key: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("msrpc_reg_enum_key: query failed\n"));
	}

	return res1;
}

static void reg_display_key_info(const char *full_name,
				const char *name, time_t key_mod_time)
{
	display_reg_key_info(out_hnd, ACTION_HEADER   , name, key_mod_time);
	display_reg_key_info(out_hnd, ACTION_ENUMERATE, name, key_mod_time);
	display_reg_key_info(out_hnd, ACTION_FOOTER   , name, key_mod_time);
}

static void reg_display_val_info(const char *full_name,
				const char* name,
				uint32 type,
				const BUFFER2 *const value)
{
	display_reg_value_info(out_hnd, ACTION_HEADER   , name, type, value);
	display_reg_value_info(out_hnd, ACTION_ENUMERATE, name, type, value);
	display_reg_value_info(out_hnd, ACTION_FOOTER   , name, type, value);
}

/****************************************************************************
nt registry enum
****************************************************************************/
void cmd_reg_enum(struct client_info *info, int argc, char *argv[])
{
	pstring full_keyname;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "regenum <key_name>\n");
		return;
	}

	split_server_keyname(srv_name, full_keyname, argv[1]);

	(void)(msrpc_reg_enum_key(srv_name, full_keyname,
				reg_display_key,
				reg_display_key_info,
				reg_display_val_info));
}

/****************************************************************************
nt registry query value info
****************************************************************************/
void cmd_reg_query_info(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res1 = True;
	BOOL res2 = True;

	POLICY_HND key_pol;
	POLICY_HND pol_con;
	pstring full_keyname;
	fstring key_name;
	fstring keyname;
	fstring val_name;

	/*
	 * query value info
	 */

	BUFFER2 buf;
	uint32 type;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "regvalinfo value_name\n");
		return;
	}

	split_server_keyname(srv_name, full_keyname, argv[1]);

	reg_get_subkey(full_keyname, keyname, val_name);

	if (keyname[0] == 0 || val_name[0] == 0)
	{
		report(out_hnd, "invalid value name\n");
		return;
	}
	
	/* open registry receive a policy handle */
	res = res ? reg_connect(srv_name, keyname, key_name, 
                                SEC_RIGHTS_MAXIMUM_ALLOWED, &pol_con) : False;

	if ((*key_name) != 0)
	{
		/* open an entry */
		res1 = res  ? reg_open_entry(&pol_con, key_name, 
                                             SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                             &key_pol) : False;
	}
	else
	{
		memcpy(&key_pol, &pol_con, sizeof(key_pol));
	}

	/* query it */
	res2 = res1 ? reg_query_info(&key_pol,
	                        val_name, &type, &buf) : False;

	if (res2)
	{
		reg_display_val_info(full_keyname, val_name, type, &buf);
	}

	/* close the handles */
	if ((*key_name) != 0)
	{
		res1 = res1 ? reg_close(&key_pol) : False;
	}
	res  = res  ? reg_close(&pol_con) : False;

	if (res2)
	{
		DEBUG(5,("cmd_reg_query: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_reg_query: query failed\n"));
	}
}

/****************************************************************************
nt registry query key
****************************************************************************/
void cmd_reg_query_key(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res1 = True;

	POLICY_HND key_pol;
	POLICY_HND pol_con;
	pstring full_keyname;
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

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "regquery key_name\n");
		return;
	}

	split_server_keyname(srv_name, full_keyname, argv[1]);

	/* open registry receive a policy handle */
	res = res ? reg_connect(srv_name, full_keyname, key_name, 
                                SEC_RIGHTS_MAXIMUM_ALLOWED, &pol_con) : False;

	if ((*key_name) != 0)
	{
		/* open an entry */
		res1 = res  ? reg_open_entry(&pol_con, key_name, 
                                             SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                             &key_pol) : False;
	}
	else
	{
		memcpy(&key_pol, &pol_con, sizeof(key_pol));
	}

	res1 = res1 ? reg_query_key(&key_pol,
				key_class, &key_class_len,
	                        &num_subkeys, &max_subkeylen, &max_subkeysize,
				&num_values, &max_valnamelen, &max_valbufsize,
	                        &sec_desc, &mod_time) : False;

	if (res1 && key_class_len != 0)
	{
		res1 = res1 ? reg_query_key(&key_pol,
				key_class, &key_class_len,
	                        &num_subkeys, &max_subkeylen, &max_subkeysize,
				&num_values, &max_valnamelen, &max_valbufsize,
	                        &sec_desc, &mod_time) : False;
	}

	if (res1)
	{
		report(out_hnd,"Registry Query Info Key\n");
		report(out_hnd,"key class: %s\n", key_class);
		report(out_hnd,"subkeys, max_len, max_size: %d %d %d\n", num_subkeys, max_subkeylen, max_subkeysize);
		report(out_hnd,"vals, max_len, max_size: 0x%x 0x%x 0x%x\n", num_values, max_valnamelen, max_valbufsize);
		report(out_hnd,"sec desc: 0x%x\n", sec_desc);
		report(out_hnd,"mod time: %s\n", http_timestring(nt_time_to_unix(&mod_time)));
	}

	/* close the handles */
	if ((*key_name) != 0)
	{
		res1 = res1 ? reg_close(&key_pol) : False;
	}
	res  = res  ? reg_close(&pol_con) : False;

	if (res && res1)
	{
		DEBUG(5,("cmd_reg_query: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_reg_query: query failed\n"));
	}
}

static struct field_info reg_val_types[] =
{
	{ 1, "UNISTR" },
	{ 3, "BYTES" },
	{ 4, "DWORD" },
};

/****************************************************************************
nt registry create value
****************************************************************************/
void cmd_reg_create_val(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND parent_pol;
	POLICY_HND pol_con;
	pstring full_keyname;
	fstring keyname;
	fstring parent_name;
	fstring val_name;
	uint32 val_type;
	BUFFER3 value;

#if 0
	uint32 unk_0;
	uint32 unk_1;
	/* query it */
	res1 = res1 ? reg_query_info(&val_pol,
	                        type, &unk_0, &unk_1) : False;
#endif

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 4)
	{
		report(out_hnd, "regcreate <val_name> <val_type> <val>\n");
		report(out_hnd, "(val_type UNISTR, BYTES, DWORD supported\n");
		return;
	}

	split_server_keyname(srv_name, full_keyname, argv[1]);

	reg_get_subkey(full_keyname, keyname, val_name);

	argc--;
	argv++;

	if (keyname[0] == 0)
	{
		report(out_hnd, "invalid key name\n");
		return;
	}
	
	if (argc < 2)
	{
		return;
	}

	argc--;
	argv++;

	val_type = str_to_enum_field(argv[0], &reg_val_types, 0);

	if (val_type != 1 && val_type != 3 && val_type != 4)
	{
		report(out_hnd, "val_type UNISTR, BYTES, DWORD supported\n");
		return;
	}

	argc--;
	argv++;

	switch (val_type)
	{
		case 0x01: /* UNISTR */
		{
			make_buffer3_str(&value, argv[0], strlen(argv[0])+1);
			break;
		}
		case 0x03: /* BYTES */
		{
			make_buffer3_hex(&value, argv[0]);
			break;
		}
		case 0x04: /* DWORD */
		{
			make_buffer3_uint32(&value, get_number(argv[0]));
			break;
		}
		default:
		{
			report(out_hnd, "i told you i only deal with UNISTR, DWORD and BYTES!\n");
			return;
		}
	}
		
	DEBUG(10,("key data:\n"));
	dump_data(10, (char *)value.buffer, value.buf_len);

	/* open registry receive a policy handle */
	res = res ? reg_connect(srv_name, keyname, parent_name, 
                                SEC_RIGHTS_MAXIMUM_ALLOWED, &pol_con) : False;

	if ((*parent_name) != 0)
	{
		/* open an entry */
		res3 = res  ? reg_open_entry(&pol_con, parent_name, 
                                             SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                             &parent_pol) : False;
	}
	else
	{
		memcpy(&parent_pol, &pol_con, sizeof(parent_pol));
	}

	/* create an entry */
	res4 = res3 ? reg_create_val(&parent_pol,
				 val_name, val_type, &value) : False;

	/* flush the modified key */
	res4 = res4 ? reg_flush_key(&parent_pol) : False;

	/* close the val handle */
	if ((*val_name) != 0)
	{
		res3 = res3 ? reg_close(&parent_pol) : False;
	}

	/* close the registry handles */
	res  = res  ? reg_close(&pol_con) : False;

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_create_val: query succeeded\n"));
		report(out_hnd,"OK\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_create_val: query failed\n"));
	}
}

/****************************************************************************
nt registry delete value
****************************************************************************/
void cmd_reg_delete_val(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND parent_pol;
	POLICY_HND pol_con;
	pstring full_keyname;
	fstring keyname;
	fstring parent_name;
	fstring val_name;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "regdelete <val_name>\n");
		return;
	}

	split_server_keyname(srv_name, full_keyname, argv[1]);

	reg_get_subkey(full_keyname, keyname, val_name);

	if (keyname[0] == 0 || val_name[0] == 0)
	{
		report(out_hnd, "invalid key name\n");
		return;
	}
	
	/* open registry receive a policy handle */
	res = res ? reg_connect(srv_name, keyname, parent_name, 
                                SEC_RIGHTS_MAXIMUM_ALLOWED, &pol_con) : False;

	if ((*val_name) != 0)
	{
		/* open an entry */
		res3 = res  ? reg_open_entry(&pol_con, parent_name, 
                                             SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                             &parent_pol) : False;
	}
	else
	{
		memcpy(&parent_pol, &pol_con, sizeof(parent_pol));
	}

	/* delete an entry */
	res4 = res3 ? reg_delete_val(&parent_pol, val_name) : False;

	/* flush the modified key */
	res4 = res4 ? reg_flush_key(&parent_pol) : False;

	/* close the key handle */
	res3 = res3 ? reg_close(&parent_pol) : False;

	/* close the registry handles */
	res  = res  ? reg_close(&pol_con) : False;

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_delete_val: query succeeded\n"));
		report(out_hnd,"OK\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_delete_val: query failed\n"));
	}
}

/****************************************************************************
nt registry delete key
****************************************************************************/
void cmd_reg_delete_key(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND parent_pol;
	POLICY_HND pol_con;
	pstring full_keyname;
	fstring parent_name;
	fstring key_name;
	fstring subkey_name;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "regdeletekey <key_name>\n");
		return;
	}

	split_server_keyname(srv_name, full_keyname, argv[1]);

	reg_get_subkey(full_keyname, parent_name, subkey_name);

	if (parent_name[0] == 0 || subkey_name[0] == 0)
	{
		report(out_hnd, "invalid key name\n");
		return;
	}
	
	/* open registry receive a policy handle */
	res = res ? reg_connect(srv_name, parent_name, key_name,
                                SEC_RIGHTS_MAXIMUM_ALLOWED, &pol_con) : False;

	if ((*key_name) != 0)
	{
		/* open an entry */
		res3 = res  ? reg_open_entry(&pol_con, key_name, 
                                             SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                             &parent_pol) : False;
	}
	else
	{
		memcpy(&parent_pol, &pol_con, sizeof(parent_pol));
	}

	/* create an entry */
	res4 = res3 ? reg_delete_key(&parent_pol, subkey_name) : False;

	/* flush the modified key */
	res4 = res4 ? reg_flush_key(&parent_pol) : False;

	/* close the key handle */
	if ((*key_name) != 0)
	{
		res3 = res3 ? reg_close(&parent_pol) : False;
	}

	/* close the registry handles */
	res  = res  ? reg_close(&pol_con) : False;

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_delete_key: query succeeded\n"));
		report(out_hnd,"OK\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_delete_key: query failed\n"));
	}
}

/****************************************************************************
nt registry create key
****************************************************************************/
void cmd_reg_create_key(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND parent_pol;
	POLICY_HND key_pol;
	POLICY_HND pol_con;
	pstring full_keyname;
	fstring parent_key;
	fstring parent_name;
	fstring key_name;
	fstring key_class;
	SEC_ACCESS sam_access;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "regcreate <key_name> [key_class]\n");
		return;
	}

	split_server_keyname(srv_name, full_keyname, argv[1]);

	reg_get_subkey(full_keyname, parent_key, key_name);

	if (parent_key[0] == 0 || key_name[0] == 0)
	{
		report(out_hnd, "invalid key name\n");
		return;
	}
	
	if (argc > 2)
	{
		fstrcpy(key_class, argv[2]);
	}
	else
	{
		memset(key_class, 0, sizeof(key_class));
	}

	/* set access permissions */
	sam_access.mask = SEC_RIGHTS_READ;

	/* open registry receive a policy handle */
	res = res ? reg_connect(srv_name, parent_key, parent_name, 
                                SEC_RIGHTS_MAXIMUM_ALLOWED, &pol_con) : False;

	if ((*parent_name) != 0)
	{
		/* open an entry */
		res3 = res  ? reg_open_entry(&pol_con, parent_name, 
                                             SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                             &parent_pol) : False;
	}
	else
	{
		memcpy(&parent_pol, &pol_con, sizeof(parent_pol));
	}

	/* create an entry */
	res4 = res3 ? reg_create_key(&parent_pol,
				 key_name, key_class, &sam_access, &key_pol) : False;

	/* flush the modified key */
	res4 = res4 ? reg_flush_key(&parent_pol) : False;

	/* close the key handle */
	res4 = res4 ? reg_close(&key_pol) : False;

	/* close the key handle */
	if ((*parent_name) != 0)
	{
		res3 = res3 ? reg_close(&parent_pol) : False;
	}

	/* close the registry handles */
	res  = res  ? reg_close(&pol_con) : False;

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_create_key: query succeeded\n"));
		report(out_hnd,"OK\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_create_key: query failed\n"));
	}
}

/****************************************************************************
nt registry security info
****************************************************************************/
void cmd_reg_test_key_sec(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND key_pol;
	POLICY_HND pol_con;
	pstring full_keyname;
	fstring key_name;

	/*
	 * security info
	 */

	uint32 sec_buf_size;
	SEC_DESC_BUF sec_buf;
	uint32 sec_info = 0x7;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "regtestkeysec <key_name>\n");
		return;
	}

	split_server_keyname(srv_name, full_keyname, argv[1]);

	/* open registry receive a policy handle */
	res = res ? reg_connect(srv_name, full_keyname, key_name, 
                                SEC_RIGHTS_MAXIMUM_ALLOWED, &pol_con) : False;

	if ((*key_name) != 0)
	{
		/* open an entry */
		res3 = res  ? reg_open_entry(&pol_con, key_name, 
                                             SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                             &key_pol) : False;
	}
	else
	{
		memcpy(&key_pol, &pol_con, sizeof(key_pol));
	}

	/* open an entry */
	res3 = res ? reg_open_entry(&pol_con, key_name, 
                                    SEC_RIGHTS_MAXIMUM_ALLOWED, &key_pol) : False;

	/* query key sec info.  first call sets sec_buf_size. */
	sec_buf_size = 1024;
	ZERO_STRUCT(sec_buf);

	res4 = res3 ? reg_get_key_sec(&key_pol,
	                        sec_info,
				&sec_buf_size, &sec_buf) : False;
	
	if (res4)
	{
		free_sec_desc_buf(&sec_buf);
	}

	res4 = res4 ? reg_get_key_sec(&key_pol,
	                        sec_info,
				&sec_buf_size, &sec_buf) : False;

	if (res4 && sec_buf.len > 0 && sec_buf.sec != NULL)
	{
		display_sec_desc(out_hnd, ACTION_HEADER   , sec_buf.sec);
		display_sec_desc(out_hnd, ACTION_ENUMERATE, sec_buf.sec);
		display_sec_desc(out_hnd, ACTION_FOOTER   , sec_buf.sec);

		res4 = res4 ? reg_set_key_sec(&key_pol,
				sec_info, sec_buf_size, sec_buf.sec) : False;

		free_sec_desc_buf(&sec_buf);
	}

	/* close the key handle */
	if ((*key_name) != 0)
	{
		res3 = res3 ? reg_close(&key_pol) : False;
	}

	/* close the registry handles */
	res  = res  ? reg_close(&pol_con) : False;

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_test2: query succeeded\n"));
		report(out_hnd,"Registry Test2\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_test2: query failed\n"));
	}
}

/****************************************************************************
nt registry security info
****************************************************************************/
void cmd_reg_get_key_sec(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;
	BOOL res3 = True;
	BOOL res4 = True;

	POLICY_HND key_pol;
	POLICY_HND pol_con;
	pstring full_keyname;
	fstring key_name;

	/*
	 * security info
	 */

	uint32 sec_buf_size;
	SEC_DESC_BUF sec_buf;
	uint32 sec_info = 0x7;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd, "reggetsec <key_name>\n");
		return;
	}

	split_server_keyname(srv_name, full_keyname, argv[1]);

	/* open registry receive a policy handle */
	res = res ? reg_connect(srv_name, full_keyname, key_name, 
                                SEC_RIGHTS_MAXIMUM_ALLOWED, &pol_con) : False;

	if ((*key_name) != 0)
	{
		/* open an entry */
		res3 = res  ? reg_open_entry(&pol_con, key_name, 
                                             SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                             &key_pol) : False;
	}
	else
	{
		memcpy(&key_pol, &pol_con, sizeof(key_pol));
	}

	/* open an entry */
	res3 = res ? reg_open_entry(&pol_con, key_name, 
                                    SEC_RIGHTS_MAXIMUM_ALLOWED, 
                                    &key_pol) : False;

	/* query key sec info.  first call sets sec_buf_size. */
	sec_buf_size = 0;
	ZERO_STRUCT(sec_buf);

	res4 = res3 ? reg_get_key_sec(&key_pol,
				sec_info,
	                        &sec_buf_size, &sec_buf) : False;
	
	if (res4)
	{
		free_sec_desc_buf(&sec_buf);
	}

	res4 = res4 ? reg_get_key_sec(&key_pol,
				sec_info,
	                        &sec_buf_size, &sec_buf) : False;

	if (res4 && sec_buf.len > 0 && sec_buf.sec != NULL)
	{
		display_sec_desc(out_hnd, ACTION_HEADER   , sec_buf.sec);
		display_sec_desc(out_hnd, ACTION_ENUMERATE, sec_buf.sec);
		display_sec_desc(out_hnd, ACTION_FOOTER   , sec_buf.sec);

		free(sec_buf.sec);
	}

	/* close the key handle */
	if ((*key_name) != 0)
	{
		res3 = res3 ? reg_close(&key_pol) : False;
	}

	/* close the registry handles */
	res  = res  ? reg_close(&pol_con) : False;

	if (res && res3 && res4)
	{
		DEBUG(5,("cmd_reg_get_key_sec: query succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_reg_get_key_sec: query failed\n"));
	}
}

/****************************************************************************
nt registry shutdown
****************************************************************************/
void cmd_reg_shutdown(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;

	fstring msg;
	uint32 timeout = 20;
	uint16 flgs = 0;
	int opt;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	msg[0] = 0;

	while ((opt = getopt(argc, argv,"fim:t:r-")) != EOF)
	{
		switch (opt)
		{
			case 'm':
			{
				safe_strcpy(msg, optarg, sizeof(msg)-1);
				break;
			}
			case 't':
			{
				timeout = atoi(optarg);
				break;
			}
			case 'r':
			{
				flgs |= 0x100;
				break;
			}
			case 'f':
			{
				flgs |= 0x001;
				break;
			}
			case '-':
			{
				if (strequal(optarg, "-reboot"))
				{
					flgs |= 0x100;
				}
				if (strequal(optarg, "-force-close"))
				{
					flgs |= 0x001;
				}
				break;
			}
		}
	}

	/* create an entry */
	res = res ? reg_shutdown(srv_name, msg, timeout, flgs) : False;

	if (res)
	{
		DEBUG(5,("cmd_reg_shutdown: query succeeded\n"));
		report(out_hnd,"OK\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_shutdown: query failed\n"));
		report(out_hnd,"Failed\n");
	}
}

/****************************************************************************
abort a shutdown
****************************************************************************/
void cmd_reg_abort_shutdown(struct client_info *info, int argc, char *argv[])
{
	BOOL res = True;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	res = res ? reg_abort_shutdown(srv_name) : False;

	if (res)
	{
		DEBUG(5,("cmd_reg_abort_shutdown: query succeeded\n"));
		report(out_hnd,"OK\n");
	}
	else
	{
		DEBUG(5,("cmd_reg_abort_shutdown: query failed\n"));
		report(out_hnd,"Failed\n");
	}
}
