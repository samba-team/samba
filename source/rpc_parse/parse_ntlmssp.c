
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

extern int DEBUGLEVEL;


/*******************************************************************
checks an RPC_HDR_AUTH structure.
********************************************************************/
BOOL rpc_hdr_ntlmssp_auth_chk(RPC_HDR_AUTH *rai)
{
	return (rai->auth_type == 0x0a && rai->auth_level == 0x06);
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_NEG structure.
********************************************************************/
BOOL make_rpc_auth_ntlmssp_neg(RPC_AUTH_NTLMSSP_NEG *neg,
				uint32 neg_flgs,
				fstring myname, fstring domain)
{
	int len_myname = strlen(myname);
	int len_domain = strlen(domain);

	if (neg == NULL) return False;

	neg->neg_flgs = neg_flgs ; /* 0x00b2b3 */

	make_str_hdr(&neg->hdr_domain, len_domain, len_domain, 0x20 + len_myname); 
	make_str_hdr(&neg->hdr_myname, len_myname, len_myname, 0x20); 

	fstrcpy(neg->myname, myname);
	fstrcpy(neg->domain, domain);

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_NEG structure.

*** lkclXXXX HACK ALERT! ***

********************************************************************/
BOOL smb_io_rpc_auth_ntlmssp_neg(char *desc, RPC_AUTH_NTLMSSP_NEG *neg, prs_struct *ps, int depth)
{
	int start_offset = ps->offset;
	if (neg == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_neg");
	depth++;

	prs_uint32("neg_flgs ", ps, depth, &(neg->neg_flgs));

	if (ps->io)
	{
		uint32 old_offset;

		/* reading */

		ZERO_STRUCTP(neg);

		smb_io_strhdr("hdr_domain", &(neg->hdr_domain), ps, depth); 
		smb_io_strhdr("hdr_myname", &(neg->hdr_myname), ps, depth); 

		old_offset = ps->offset;

		ps->offset = neg->hdr_myname  .buffer + start_offset - 12;
		prs_uint8s(True , "myname", ps, depth, (uint8*)neg->myname  , MIN(neg->hdr_myname  .str_str_len, sizeof(neg->myname  ))); 
		old_offset += neg->hdr_myname  .str_str_len;

		ps->offset = neg->hdr_domain  .buffer + start_offset - 12; 
		prs_uint8s(True , "domain", ps, depth, (uint8*)neg->domain  , MIN(neg->hdr_domain  .str_str_len, sizeof(neg->domain  ))); 
		old_offset += neg->hdr_domain  .str_str_len;

		ps->offset = old_offset;
	}
	else
	{
		/* writing */
		smb_io_strhdr("hdr_domain", &(neg->hdr_domain), ps, depth); 
		smb_io_strhdr("hdr_myname", &(neg->hdr_myname), ps, depth); 

		prs_uint8s(True , "myname", ps, depth, (uint8*)neg->myname  , MIN(neg->hdr_myname  .str_str_len, sizeof(neg->myname  ))); 
		prs_uint8s(True , "domain", ps, depth, (uint8*)neg->domain  , MIN(neg->hdr_domain  .str_str_len, sizeof(neg->domain  ))); 
	}

	return True;
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_CHAL structure.
********************************************************************/
BOOL make_rpc_auth_ntlmssp_chal(RPC_AUTH_NTLMSSP_CHAL *chl,
				uint32 neg_flags,
				uint8 challenge[8])
{
	if (chl == NULL) return False;

	chl->unknown_1 = 0x0; 
	chl->unknown_2 = 0x00000028;
	chl->neg_flags = neg_flags; /* 0x0082b1 */

	memcpy(chl->challenge, challenge, sizeof(chl->challenge)); 
	bzero (chl->reserved ,            sizeof(chl->reserved)); 

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_CHAL structure.
********************************************************************/
BOOL smb_io_rpc_auth_ntlmssp_chal(char *desc, RPC_AUTH_NTLMSSP_CHAL *chl, prs_struct *ps, int depth)
{
	if (chl == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_chal");
	depth++;

	prs_uint32("unknown_1", ps, depth, &(chl->unknown_1)); /* 0x0000 0000 */
	prs_uint32("unknown_2", ps, depth, &(chl->unknown_2)); /* 0x0000 b2b3 */
	prs_uint32("neg_flags", ps, depth, &(chl->neg_flags)); /* 0x0000 82b1 */

	prs_uint8s (False, "challenge", ps, depth, chl->challenge, sizeof(chl->challenge));
	prs_uint8s (False, "reserved ", ps, depth, chl->reserved , sizeof(chl->reserved ));

	return True;
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_RESP structure.

*** lkclXXXX FUDGE!  HAVE TO MANUALLY SPECIFY OFFSET HERE (0x1c bytes) ***
*** lkclXXXX the actual offset is at the start of the auth verifier    ***

********************************************************************/
BOOL make_rpc_auth_ntlmssp_resp(RPC_AUTH_NTLMSSP_RESP *rsp,
				uchar lm_resp[24],
				uchar *nt_resp, size_t nt_len,
				char *domain, char *user, char *wks,
				uint32 neg_flags)
{
	uint32 offset;
	int dom_len = strlen(domain);
	int wks_len = strlen(wks   );
	int usr_len = strlen(user  );
	int lm_len  = nt_len != 0 ? (lm_resp != NULL ? 24 : 0) : 1;

	DEBUG(5,("make_rpc_auth_ntlmssp_resp\n"));

	if (rsp == NULL) return False;

#ifdef DEBUG_PASSWORD
	DEBUG(100,("lm_resp\n"));
	if (lm_resp != NULL)
	{
		dump_data(100, lm_resp, lm_len);
	}
	DEBUG(100,("nt_resp\n"));
	if (nt_resp != NULL)
	{
		dump_data(100, nt_resp, nt_len);
	}
#endif

	DEBUG(6,("dom: %s user: %s wks: %s neg_flgs: 0x%x\n",
	          domain, user, wks, neg_flags));

	offset = 0x40;

	if (IS_BITS_SET_ALL(neg_flags, NTLMSSP_NEGOTIATE_UNICODE))
	{
		dom_len *= 2;
		wks_len *= 2;
		usr_len *= 2;
	}

	make_str_hdr(&rsp->hdr_domain , dom_len, dom_len, offset);
	offset += dom_len;

	make_str_hdr(&rsp->hdr_usr    , usr_len, usr_len, offset);
	offset += usr_len;

	make_str_hdr(&rsp->hdr_wks    , wks_len, wks_len, offset);
	offset += wks_len;

	make_str_hdr(&rsp->hdr_lm_resp, lm_len , lm_len , offset);
	offset += lm_len;

	make_str_hdr(&rsp->hdr_nt_resp, nt_len , nt_len , offset);
	offset += nt_len;

	make_str_hdr(&rsp->hdr_sess_key, 0, 0, offset);

	rsp->neg_flags = neg_flags;

	if (lm_resp != NULL && lm_len != 1)
	{
		memcpy(rsp->lm_resp, lm_resp, lm_len);
	}
	else
	{
		rsp->lm_resp[0] = 0;
	}
	if (nt_resp != NULL)
	{
		memcpy(rsp->nt_resp, nt_resp, nt_len);
	}
	else
	{
		rsp->nt_resp[0] = 0;
	}

	if (IS_BITS_SET_ALL(neg_flags, NTLMSSP_NEGOTIATE_UNICODE))
	{
		ascii_to_unibuf(rsp->domain, domain, sizeof(rsp->domain)-2);
		ascii_to_unibuf(rsp->user  , user  , sizeof(rsp->user  )-2);
		ascii_to_unibuf(rsp->wks   , wks   , sizeof(rsp->wks   )-2);
	}
	else
	{
		fstrcpy(rsp->domain, domain);
		fstrcpy(rsp->user  , user  );
		fstrcpy(rsp->wks   , wks   );
	}
	rsp->sess_key[0] = 0;

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_RESP structure.

*** lkclXXXX FUDGE!  HAVE TO MANUALLY SPECIFY OFFSET HERE (0x1c bytes) ***
*** lkclXXXX the actual offset is at the start of the auth verifier    ***

********************************************************************/
BOOL smb_io_rpc_auth_ntlmssp_resp(char *desc, RPC_AUTH_NTLMSSP_RESP *rsp, prs_struct *ps, int depth)
{
	if (rsp == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_resp");
	depth++;

	if (ps->io)
	{
		uint32 old_offset;

		/* reading */

		ZERO_STRUCTP(rsp);

		smb_io_strhdr("hdr_lm_resp ", &rsp->hdr_lm_resp , ps, depth); 
		smb_io_strhdr("hdr_nt_resp ", &rsp->hdr_nt_resp , ps, depth); 
		smb_io_strhdr("hdr_domain  ", &rsp->hdr_domain  , ps, depth); 
		smb_io_strhdr("hdr_user    ", &rsp->hdr_usr     , ps, depth); 
		smb_io_strhdr("hdr_wks     ", &rsp->hdr_wks     , ps, depth); 
		smb_io_strhdr("hdr_sess_key", &rsp->hdr_sess_key, ps, depth); 

		prs_uint32("neg_flags", ps, depth, &(rsp->neg_flags)); /* 0x0000 82b1 */

		old_offset = ps->offset;

		ps->offset = rsp->hdr_domain  .buffer + 0xc;
		prs_uint8s(True , "domain  ", ps, depth, (uint8*)rsp->domain  , MIN(rsp->hdr_domain  .str_str_len, sizeof(rsp->domain  ))); 
		old_offset += rsp->hdr_domain  .str_str_len;

		ps->offset = rsp->hdr_usr     .buffer + 0xc;
		prs_uint8s(True , "user    ", ps, depth, (uint8*)rsp->user    , MIN(rsp->hdr_usr     .str_str_len, sizeof(rsp->user    ))); 
		old_offset += rsp->hdr_usr     .str_str_len;

		ps->offset = rsp->hdr_wks     .buffer + 0xc;
		prs_uint8s(True , "wks     ", ps, depth, (uint8*)rsp->wks     , MIN(rsp->hdr_wks     .str_str_len, sizeof(rsp->wks     ))); 
		old_offset += rsp->hdr_wks     .str_str_len;

		ps->offset = rsp->hdr_lm_resp .buffer + 0xc;
		prs_uint8s(False, "lm_resp ", ps, depth, (uint8*)rsp->lm_resp , MIN(rsp->hdr_lm_resp .str_str_len, sizeof(rsp->lm_resp ))); 
		old_offset += rsp->hdr_lm_resp .str_str_len;

		ps->offset = rsp->hdr_nt_resp .buffer + 0xc;
		prs_uint8s(False, "nt_resp ", ps, depth, (uint8*)rsp->nt_resp , MIN(rsp->hdr_nt_resp .str_str_len, sizeof(rsp->nt_resp ))); 
		old_offset += rsp->hdr_nt_resp .str_str_len;

		if (rsp->hdr_sess_key.str_str_len != 0)
		{
			ps->offset = rsp->hdr_sess_key.buffer + 0x10;
			old_offset += rsp->hdr_sess_key.str_str_len;
			prs_uint8s(False, "sess_key", ps, depth, (uint8*)rsp->sess_key, MIN(rsp->hdr_sess_key.str_str_len, sizeof(rsp->sess_key))); 
		}

		ps->offset = old_offset;
	}
	else
	{
		/* writing */
		smb_io_strhdr("hdr_lm_resp ", &rsp->hdr_lm_resp , ps, depth); 
		smb_io_strhdr("hdr_nt_resp ", &rsp->hdr_nt_resp , ps, depth); 
		smb_io_strhdr("hdr_domain  ", &rsp->hdr_domain  , ps, depth); 
		smb_io_strhdr("hdr_user    ", &rsp->hdr_usr     , ps, depth); 
		smb_io_strhdr("hdr_wks     ", &rsp->hdr_wks     , ps, depth); 
		smb_io_strhdr("hdr_sess_key", &rsp->hdr_sess_key, ps, depth); 

		prs_uint32("neg_flags", ps, depth, &(rsp->neg_flags)); /* 0x0000 82b1 */

		prs_uint8s(True , "domain  ", ps, depth, (uint8*)rsp->domain  , MIN(rsp->hdr_domain  .str_str_len, sizeof(rsp->domain  ))); 
		prs_uint8s(True , "user    ", ps, depth, (uint8*)rsp->user    , MIN(rsp->hdr_usr     .str_str_len, sizeof(rsp->user    ))); 
		prs_uint8s(True , "wks     ", ps, depth, (uint8*)rsp->wks     , MIN(rsp->hdr_wks     .str_str_len, sizeof(rsp->wks     ))); 
		prs_uint8s(False, "lm_resp ", ps, depth, (uint8*)rsp->lm_resp , MIN(rsp->hdr_lm_resp .str_str_len, sizeof(rsp->lm_resp ))); 
		prs_uint8s(False, "nt_resp ", ps, depth, (uint8*)rsp->nt_resp , MIN(rsp->hdr_nt_resp .str_str_len, sizeof(rsp->nt_resp ))); 
		prs_uint8s(False, "sess_key", ps, depth, (uint8*)rsp->sess_key, MIN(rsp->hdr_sess_key.str_str_len, sizeof(rsp->sess_key))); 
	}

	return True;
}

/*******************************************************************
checks an RPC_AUTH_NTLMSSP_CHK structure.
********************************************************************/
BOOL rpc_auth_ntlmssp_chk(RPC_AUTH_NTLMSSP_CHK *chk, uint32 crc32, uint32 seq_num)
{
	if (chk == NULL)
	{
		return False;
	}

	if (chk->crc32 != crc32 ||
	    chk->ver   != NTLMSSP_SIGN_VERSION ||
	    chk->seq_num != seq_num)
	{
		DEBUG(5,("verify failed - crc %x ver %x seq %d\n",
			crc32, NTLMSSP_SIGN_VERSION, seq_num));
		DEBUG(5,("verify expect - crc %x ver %x seq %d\n",
			chk->crc32, chk->ver, chk->seq_num));
		return False;
	}
	return True;
}

/*******************************************************************
creates an RPC_AUTH_NTLMSSP_CHK structure.
********************************************************************/
BOOL make_rpc_auth_ntlmssp_chk(RPC_AUTH_NTLMSSP_CHK *chk,
				uint32 ver, uint32 crc32, uint32 seq_num)
{
	if (chk == NULL) return False;

	chk->ver      = ver     ;
	chk->reserved = 0x0;
	chk->crc32    = crc32   ;
	chk->seq_num  = seq_num ;

	return True;
}

/*******************************************************************
reads or writes an RPC_AUTH_NTLMSSP_CHK structure.
********************************************************************/
BOOL smb_io_rpc_auth_ntlmssp_chk(char *desc, RPC_AUTH_NTLMSSP_CHK *chk, prs_struct *ps, int depth)
{
	if (chk == NULL) return False;

	prs_debug(ps, depth, desc, "smb_io_rpc_auth_ntlmssp_chk");
	depth++;

	prs_uint32("ver     ", ps, depth, &(chk->ver     )); 
	prs_uint32("reserved", ps, depth, &(chk->reserved)); 
	prs_uint32("crc32   ", ps, depth, &(chk->crc32   )); 
	prs_uint32("seq_num ", ps, depth, &(chk->seq_num )); 

	return True;
}

