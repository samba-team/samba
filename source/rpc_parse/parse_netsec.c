
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
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
#include "rpc_parse.h"

extern int DEBUGLEVEL;


/*******************************************************************
checks an RPC_HDR_AUTH structure.
********************************************************************/
BOOL rpc_hdr_netsec_auth_chk(RPC_HDR_AUTH *rai)
{
	return (rai->auth_type == 0x44 && rai->auth_level == 0x06);
}

/*******************************************************************
creates an RPC_AUTH_NETSEC_NEG structure.
********************************************************************/
BOOL make_rpc_auth_netsec_neg(RPC_AUTH_NETSEC_NEG *neg,
				fstring domain,
				fstring myname)
{
	if (neg == NULL) return False;

	fstrcpy(neg->domain, domain);
	fstrcpy(neg->myname, myname);

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NETSEC_NEG structure.

*** lkclXXXX HACK ALERT! ***

********************************************************************/
BOOL smb_io_rpc_auth_netsec_neg(char *desc, RPC_AUTH_NETSEC_NEG *neg, prs_struct *ps, int depth)
{
	if (neg == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_netsec_neg");
	depth++;

	prs_string("domain", ps, depth, neg->domain, 0, sizeof(neg->domain)); 
	prs_string("myname", ps, depth, neg->myname, 0, sizeof(neg->myname)); 

	return True;
}

/*******************************************************************
creates an RPC_AUTH_NETSEC_RESP structure.

*** lkclXXXX FUDGE!  HAVE TO MANUALLY SPECIFY OFFSET HERE (0x1c bytes) ***
*** lkclXXXX the actual offset is at the start of the auth verifier    ***

********************************************************************/
BOOL make_rpc_auth_netsec_resp(RPC_AUTH_NETSEC_RESP *rsp, uint32 flags)
{
	DEBUG(5,("make_rpc_auth_netsec_resp\n"));

	if (rsp == NULL) return False;

	rsp->flags = flags;

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NETSEC_RESP structure.

*** lkclXXXX FUDGE!  HAVE TO MANUALLY SPECIFY OFFSET HERE (0x1c bytes) ***
*** lkclXXXX the actual offset is at the start of the auth verifier    ***

********************************************************************/
BOOL smb_io_rpc_auth_netsec_resp(char *desc, RPC_AUTH_NETSEC_RESP *rsp, prs_struct *ps, int depth)
{
	if (rsp == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_netsec_resp");
	depth++;

	prs_uint32("flags", ps, depth, &rsp->flags); 

	return True;
}

/*******************************************************************
checks an RPC_AUTH_NETSEC_CHK structure.
********************************************************************/
BOOL rpc_auth_netsec_chk(RPC_AUTH_NETSEC_CHK *chk)
{
	static const uchar netsec_sig[8] = NETSEC_SIGNATURE;

	if (chk == NULL)
	{
		return False;
	}

	if (memcmp(chk, netsec_sig, 8) != 0)
	{
		return False;
	}
	return True;
}

/*******************************************************************
creates an RPC_AUTH_NETSEC_CHK structure.
********************************************************************/
BOOL make_rpc_auth_netsec_chk(RPC_AUTH_NETSEC_CHK *chk,
				const uchar sig[8],
				const uchar data1[8],
				const uchar data3[8],
				const uchar data8[8])
{
	if (chk == NULL) return False;

	if (sig != NULL)
	{
		memcpy(chk->sig  , sig  , sizeof(chk->sig  ));
	}
	if (data1 != NULL)
	{
		memcpy(chk->data1, data1, sizeof(chk->data1));
	}
	if (data3 != NULL)
	{
		memcpy(chk->data3, data3, sizeof(chk->data3));
	}
	if (data8 != NULL)
	{
		memcpy(chk->data8, data8, sizeof(chk->data8));
	}

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NETSEC_CHK structure.
********************************************************************/
BOOL smb_io_rpc_auth_netsec_chk(char *desc, RPC_AUTH_NETSEC_CHK *chk, prs_struct *ps, int depth)
{
	if (chk == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_netsec_chk");
	depth++;

	prs_uint8s(False, "sig  ", ps, depth, chk->sig  , sizeof(chk->sig  ));
	prs_uint8s(False, "data3", ps, depth, chk->data3, sizeof(chk->data3));
	prs_uint8s(False, "data1", ps, depth, chk->data1, sizeof(chk->data1));
	prs_uint8s(False, "data8", ps, depth, chk->data8, sizeof(chk->data8));

	return True;
}

static void netsechash(uchar *key, uchar *data, int data_len)
{
  uchar hash[256];
  uchar index_i = 0;
  uchar index_j = 0;
  uchar j = 0;
  int ind;

  for (ind = 0; ind < 256; ind++)
  {
    hash[ind] = (uchar)ind;
  }

  for( ind = 0; ind < 256; ind++)
  {
     uchar tc;

     j += (hash[ind] + key[ind%16]);

     tc = hash[ind];
     hash[ind] = hash[j];
     hash[j] = tc;
  }

  for( ind = 0; ind < data_len; ind++)
  {
    uchar tc;
    uchar t;

    index_i++;
    index_j += hash[index_i];

    tc = hash[index_i];
    hash[index_i] = hash[index_j];
    hash[index_j] = tc;

    t = hash[index_i] + hash[index_j];
    data[ind] ^= hash[t];
  }
}


BOOL netsec_encode(struct netsec_auth_struct *a,
				RPC_AUTH_NETSEC_CHK *verf,
				char *data, size_t data_len)
{
	char dataN[4];
	char digest1[16]; 
	struct MD5Context ctx3; 
	uchar sess_kf0[16];
	int i;

	/* store the sequence number */
	SIVAL(dataN, 0, a->seq_num);

	for (i = 0; i < sizeof(sess_kf0); i++)
	{
		sess_kf0[i] = a->sess_key[i] ^ 0xf0;
	}

	dump_data_pw("a->sess_key:\n", a->sess_key, sizeof(a->sess_key));
	dump_data_pw("a->seq_num :\n", dataN, sizeof(dataN));

	MD5Init(&ctx3);
	MD5Update(&ctx3, dataN, 0x4);
	MD5Update(&ctx3, verf->sig, 8);

	MD5Update(&ctx3, verf->data8, 8); 

	dump_data_pw("verf->data8:\n", verf->data8, sizeof(verf->data8));
	dump_data_pw("sess_kf0:\n", sess_kf0, sizeof(sess_kf0));

	hmac_md5(sess_kf0, dataN, 0x4, digest1 );
	dump_data_pw("digest1 (ebp-8):\n", digest1, sizeof(digest1));
	hmac_md5(digest1, verf->data3, 8, digest1);
	dump_data_pw("netsechashkey:\n", digest1, sizeof(digest1));
	netsechash(digest1, verf->data8, 8);

	dump_data_pw("verf->data8:\n", verf->data8, sizeof(verf->data8));

	dump_data_pw("data   :\n", data, data_len);
	MD5Update(&ctx3, data, data_len); 

	{
		char digest_tmp[16];
		char digest2[16];
		MD5Final(digest_tmp, &ctx3);
		hmac_md5(a->sess_key, digest_tmp, 16, digest2);
		dump_data_pw("digest_tmp:\n", digest_tmp, sizeof(digest_tmp));
		dump_data_pw("digest:\n", digest2, sizeof(digest2));
		memcpy(verf->data1, digest2, sizeof(verf->data1));
	}

	netsechash(digest1, data , data_len);
	dump_data_pw("data:\n", data, data_len);

	hmac_md5(a->sess_key, dataN , 0x4, digest1 );
	dump_data_pw("ctx:\n", digest1, sizeof(digest1));

	hmac_md5(digest1, verf->data1, 8, digest1);

	dump_data_pw("netsechashkey:\n", digest1, sizeof(digest1));

	dump_data_pw("verf->data3:\n", verf->data3, sizeof(verf->data3));
	netsechash(digest1, verf->data3, 8);
	dump_data_pw("verf->data3:\n", verf->data3, sizeof(verf->data3));


	return True;
}

BOOL netsec_decode(struct netsec_auth_struct *a,
				RPC_AUTH_NETSEC_CHK *verf,
				char *data, size_t data_len)
{
	char dataN[4];
	char digest1[16]; 
	struct MD5Context ctx3; 
	uchar sess_kf0[16];
	int i;

	/* store the sequence number */
	SIVAL(dataN, 0, a->seq_num);

	for (i = 0; i < sizeof(sess_kf0); i++)
	{
		sess_kf0[i] = a->sess_key[i] ^ 0xf0;
	}

	dump_data_pw("a->sess_key:\n", a->sess_key, sizeof(a->sess_key));
	dump_data_pw("a->seq_num :\n", dataN, sizeof(dataN));
	hmac_md5(a->sess_key, dataN , 0x4, digest1 );
	dump_data_pw("ctx:\n", digest1, sizeof(digest1));

	hmac_md5(digest1, verf->data1, 8, digest1);

	dump_data_pw("netsechashkey:\n", digest1, sizeof(digest1));
	dump_data_pw("verf->data3:\n", verf->data3, sizeof(verf->data3));
	netsechash(digest1, verf->data3, 8);
	dump_data_pw("verf->data3_dec:\n", verf->data3, sizeof(verf->data3));

	MD5Init(&ctx3);
	MD5Update(&ctx3, dataN, 0x4);
	MD5Update(&ctx3, verf->sig, 8);

	dump_data_pw("sess_kf0:\n", sess_kf0, sizeof(sess_kf0));

	hmac_md5(sess_kf0, dataN, 0x4, digest1 );
	dump_data_pw("digest1 (ebp-8):\n", digest1, sizeof(digest1));
	hmac_md5(digest1, verf->data3, 8, digest1);
	dump_data_pw("netsechashkey:\n", digest1, sizeof(digest1));

	dump_data_pw("verf->data8:\n", verf->data8, sizeof(verf->data8));
	netsechash(digest1, verf->data8, 8);
	dump_data_pw("verf->data8_dec:\n", verf->data8, sizeof(verf->data8));
	MD5Update(&ctx3, verf->data8, 8); 

	dump_data_pw("data   :\n", data, data_len);
	netsechash(digest1, data , data_len);
	dump_data_pw("datadec:\n", data, data_len);

	MD5Update(&ctx3, data, data_len); 
	{
		char digest_tmp[16];
		MD5Final(digest_tmp, &ctx3);
		hmac_md5(a->sess_key, digest_tmp, 16, digest1);
		dump_data_pw("digest_tmp:\n", digest_tmp, sizeof(digest_tmp));
	}

	dump_data_pw("digest:\n", digest1, sizeof(digest1));
	dump_data_pw("verf->data1:\n", verf->data1, sizeof(verf->data1));

	return memcmp(digest1, verf->data1, sizeof(verf->data1)) == 0;
}
