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
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

uint32 lookup_lsa_names(const char *srv_name,
			uint32 num_names, char **names,
			uint32 * num_sids, DOM_SID ** sids, uint32 ** types)
{
	BOOL res1 = True;
	BOOL res2 = True;
	POLICY_HND lsa_pol;

	if (srv_name == NULL)
	{
		srv_name = "\\\\.";
	}

	if (num_sids)
	{
		*num_sids = 0;
	}
	if (sids)
	{
		*sids = NULL;
	}
	if (types)
	{
		*types = NULL;
	}

	if (!num_sids || (!types && !sids))
	{
		/* Not sure, wether that's a good error-code */
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	res1 = res1 ? lsa_open_policy(srv_name, &lsa_pol, True,
				      0x02000000) : False;

	res2 = res1 ? lsa_lookup_names(&lsa_pol,
				       num_names, names,
				       sids, types, num_sids) : False;

	res1 = res1 ? lsa_close(&lsa_pol) : False;

	if (!res2)
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	return 0x0;
}


uint32 lookup_lsa_name(const char *domain,
		       char *name, DOM_SID * sid, uint32 * type)
{
	fstring srv_name;
	BOOL res3 = True;
	BOOL res4 = True;
	char **names = NULL;
	uint32 *types = NULL;
	int num_names = 0;
	DOM_SID *sids = NULL;
	int num_sids = 0;
	POLICY_HND lsa_pol;

	if (!get_any_dc_name(domain, srv_name))
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	num_names = 1;
	names = &name;

	/* lookup domain controller; receive a policy handle */
	res3 = res3 ? lsa_open_policy(srv_name, &lsa_pol, True,
				      0x02000000) : False;

	/* send lsa lookup sids call */
	res4 = res3 ? lsa_lookup_names(&lsa_pol,
				       num_names, names,
				       &sids, &types, &num_sids) : False;

	res3 = res3 ? lsa_close(&lsa_pol) : False;

	res4 = num_sids != 1 ? False : res4;

	if (!res4)
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}
	sid_copy(sid, &sids[0]);
	*type = types[0];

	if (types != NULL)
	{
		free(types);
	}

	if (sids != NULL)
	{
		free(sids);
	}

	return 0x0;
}

/****************************************************************************
lookup sids
****************************************************************************/
uint32 lookup_lsa_sid(const char *domain,
		      DOM_SID * sid, char *name, uint32 * type)
{
	POLICY_HND lsa_pol;
	fstring srv_name;
	DOM_SID **sids = NULL;
	uint32 num_sids = 0;
	char **names = NULL;
	int num_names = 0;
	uint32 *types = NULL;

	BOOL res = True;
	BOOL res1 = True;

	if (!get_any_dc_name(domain, srv_name))
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	add_sid_to_array(&num_sids, &sids, sid);

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name, &lsa_pol, True,
				    0x02000000) : False;

	/* send lsa lookup sids call */
	res1 = res ? lsa_lookup_sids(&lsa_pol,
				     num_sids, sids,
				     &names, &types, &num_names) : False;

	res = res ? lsa_close(&lsa_pol) : False;

	if (!res1 || names == NULL || types == NULL)
	{
		return NT_STATUS_NONE_MAPPED | 0xC0000000;
	}

	fstrcpy(name, names[0]);
	*type = types[0];

	free_sid_array(num_sids, sids);
	free_char_array(num_names, names);

	if (types != NULL)
	{
		free(types);
	}

	return 0x0;
}

/****************************************************************************
nt lsa create secret
****************************************************************************/
BOOL msrpc_lsa_create_secret(const char *srv_name, const char *secret_name,
			     uint32 access_rights)
{
	BOOL res = True;
	BOOL res1;

	POLICY_HND pol_sec;
	POLICY_HND lsa_pol;

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name,
				    &lsa_pol, True, 0x02000000) : False;

	/* lookup domain controller; receive a policy handle */
	res1 = res ? lsa_create_secret(&lsa_pol,
				       secret_name, access_rights,
				       &pol_sec) : False;

	res1 = res1 ? lsa_close(&pol_sec) : False;

	res = res ? lsa_close(&lsa_pol) : False;

	return res1;
}

/****************************************************************************
put data into secret buffer.
****************************************************************************/
void secret_store_data(STRING2 * secret, const char *data, int len)
{
	ZERO_STRUCTP(secret);

	secret->str_max_len = len + 8;
	secret->undoc = 0;
	secret->str_str_len = len + 8;

	SIVAL(secret->buffer, 0, len);
	SIVAL(secret->buffer, 4, 0x01);
	memcpy(secret->buffer + 8, data, len);
}

/****************************************************************************
put data into secret buffer.
****************************************************************************/
void secret_store_data2(STRING2 * secret, const char *data, int len)
{
	ZERO_STRUCTP(secret);

	secret->str_max_len = len;
	secret->undoc = 0;
	secret->str_str_len = len;

	memcpy(secret->buffer, data, len);
}

/****************************************************************************
nt lsa query secret
****************************************************************************/
BOOL msrpc_lsa_set_secret(const char *srv_name,
			  const char *secret_name, const char *data, int len)
{
	BOOL res = True;
	BOOL res1;
	BOOL res2;

	POLICY_HND pol_sec;
	POLICY_HND lsa_pol;
	STRING2 secret;

	secret_store_data(&secret, data, len);

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy(srv_name,
				    &lsa_pol, True, 0x02000000) : False;

	/* lookup domain controller; receive a policy handle */
	res1 = res ? lsa_open_secret(&lsa_pol,
				     secret_name, 0x02000000,
				     &pol_sec) : False;

	res2 = res1 ? (lsa_set_secret(&pol_sec, &secret) ==
		       NT_STATUS_NOPROBLEMO) : False;

	res1 = res1 ? lsa_close(&pol_sec) : False;

	res = res ? lsa_close(&lsa_pol) : False;

	return res2;
}

/****************************************************************************
nt lsa query secret
****************************************************************************/
BOOL msrpc_lsa_query_secret(const char *srv_name,
			    const char *secret_name,
			    STRING2 * secret, NTTIME * last_update)
{
	BOOL res = True;
	BOOL res1;
	BOOL res2;

	POLICY_HND pol_sec;
	POLICY_HND lsa_pol;

	/* lookup domain controller; receive a policy handle */
	res = res ? lsa_open_policy2(srv_name,
				     &lsa_pol, False, 0x02000000) : False;

	/* lookup domain controller; receive a policy handle */
	res1 = res ? lsa_open_secret(&lsa_pol,
				     secret_name, 0x02000000,
				     &pol_sec) : False;

	res2 = res1 ? lsa_query_secret(&pol_sec, secret, last_update) : False;

	res1 = res1 ? lsa_close(&pol_sec) : False;

	res = res ? lsa_close(&lsa_pol) : False;

	return res2;
}

/****************************************************************************
obtains a trust account password
****************************************************************************/
BOOL secret_get_data(const STRING2 * secret, uchar * data, uint32 * len)
{
	(*len) = IVAL(secret->buffer, 0);
	if (secret->str_str_len != (*len) + 8)
	{
		return False;
	}
	if (IVAL(secret->buffer, 4) != 0x1)
	{
		return False;
	}
	memcpy(data, secret->buffer + 8, *len);
	return True;
}

/****************************************************************************
obtains a trust account password
****************************************************************************/
BOOL secret_to_nt_owf(uchar trust_passwd[16], const STRING2 * secret)
{
	UNISTR2 uni_pwd;
	uint32 len;
	pstring data;
	int i;

	if (!secret_get_data(secret, data, &len))
	{
		return False;
	}
	for (i = 0; i < len; i++)
	{
		uni_pwd.buffer[i] = SVAL(data, i * 2);
	}
	uni_pwd.uni_str_len = len / 2;
	uni_pwd.uni_max_len = len / 2;
	nt_owf_genW(&uni_pwd, trust_passwd);

	return True;
}

/****************************************************************************
obtains a trust account password
****************************************************************************/
BOOL msrpc_lsa_query_trust_passwd(const char *srv_name,
				  const char *secret_name,
				  uchar trust_passwd[16],
				  NTTIME * last_update)
{
	STRING2 secret;

	if (!msrpc_lsa_query_secret(srv_name, secret_name, &secret,
				    last_update))
	{
		return False;
	}
	return secret_to_nt_owf(trust_passwd, &secret);
}
