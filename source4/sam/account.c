/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Jeremy Allison 		1996-2001
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
   Copyright (C) Gerald (Jerry) Carter		2000-2001
   Copyright (C) Andrew Bartlett		2001-2002
      
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SAM

/************************************************************
 Fill the SAM_ACCOUNT_HANDLE with default values.
 ***********************************************************/

static void sam_fill_default_account(SAM_ACCOUNT_HANDLE *account)
{
	ZERO_STRUCT(account->private); /* Don't touch the talloc context */

        /* Don't change these timestamp settings without a good reason.
           They are important for NT member server compatibility. */

	/* FIXME: We should actually call get_nt_time_max() or sthng 
	 * here */
	unix_to_nt_time(&(account->private.logoff_time),get_time_t_max());
	unix_to_nt_time(&(account->private.kickoff_time),get_time_t_max());
	unix_to_nt_time(&(account->private.pass_must_change_time),get_time_t_max());
	account->private.unknown_1 = 0x00ffffff; 	/* don't know */
	account->private.logon_divs = 168; 	/* hours per week */
	account->private.hours_len = 21; 		/* 21 times 8 bits = 168 */
	memset(account->private.hours, 0xff, account->private.hours_len); /* available at all hours */
	account->private.unknown_2 = 0x00000000; /* don't know */
	account->private.unknown_3 = 0x000004ec; /* don't know */
}	

static void destroy_sam_talloc(SAM_ACCOUNT_HANDLE **account) 
{
	if (*account) {
		data_blob_clear_free(&((*account)->private.lm_pw));
		data_blob_clear_free(&((*account)->private.nt_pw));
		if((*account)->private.plaintext_pw!=NULL)
			memset((*account)->private.plaintext_pw,'\0',strlen((*account)->private.plaintext_pw));

		talloc_destroy((*account)->mem_ctx);
		*account = NULL;
	}
}


/**********************************************************************
 Alloc memory and initialises a SAM_ACCOUNT_HANDLE on supplied mem_ctx.
***********************************************************************/

NTSTATUS sam_init_account_talloc(TALLOC_CTX *mem_ctx, SAM_ACCOUNT_HANDLE **account)
{
	SMB_ASSERT(*account != NULL);

	if (!mem_ctx) {
		DEBUG(0,("sam_init_account_talloc: mem_ctx was NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	*account=(SAM_ACCOUNT_HANDLE *)talloc(mem_ctx, sizeof(SAM_ACCOUNT_HANDLE));

	if (*account==NULL) {
		DEBUG(0,("sam_init_account_talloc: error while allocating memory\n"));
		return NT_STATUS_NO_MEMORY;
	}

	(*account)->mem_ctx = mem_ctx;

	(*account)->free_fn = NULL;

	sam_fill_default_account(*account);
	
	return NT_STATUS_OK;
}


/*************************************************************
 Alloc memory and initialises a struct sam_passwd.
 ************************************************************/

NTSTATUS sam_init_account(SAM_ACCOUNT_HANDLE **account)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS nt_status;
	
	mem_ctx = talloc_init("sam internal SAM_ACCOUNT_HANDLE allocation");

	if (!mem_ctx) {
		DEBUG(0,("sam_init_account: error while doing talloc_init()\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_init_account_talloc(mem_ctx, account))) {
		talloc_destroy(mem_ctx);
		return nt_status;
	}
	
	(*account)->free_fn = destroy_sam_talloc;

	return NT_STATUS_OK;
}

/**
 * Free the contents of the SAM_ACCOUNT_HANDLE, but not the structure.
 *
 * Also wipes the LM and NT hashes and plaintext password from 
 * memory.
 *
 * @param account SAM_ACCOUNT_HANDLE to free members of.
 **/

static void sam_free_account_contents(SAM_ACCOUNT_HANDLE *account)
{

	/* Kill off sensitive data.  Free()ed by the
	   talloc mechinism */

	data_blob_clear_free(&(account->private.lm_pw));
	data_blob_clear_free(&(account->private.nt_pw));
	if (account->private.plaintext_pw)
		memset(account->private.plaintext_pw,'\0',strlen(account->private.plaintext_pw));
}


/************************************************************
 Reset the SAM_ACCOUNT_HANDLE and free the NT/LM hashes.
 ***********************************************************/

NTSTATUS sam_reset_sam(SAM_ACCOUNT_HANDLE *account)
{
	SMB_ASSERT(account != NULL);
	
	sam_free_account_contents(account);

	sam_fill_default_account(account);

	return NT_STATUS_OK;
}


/************************************************************
 Free the SAM_ACCOUNT_HANDLE and the member pointers.
 ***********************************************************/

NTSTATUS sam_free_account(SAM_ACCOUNT_HANDLE **account)
{
	SMB_ASSERT(*account != NULL);

	sam_free_account_contents(*account);
	
	if ((*account)->free_fn) {
		(*account)->free_fn(account);
	}

	return NT_STATUS_OK;	
}


/**********************************************************
 Encode the account control bits into a string.
 length = length of string to encode into (including terminating
 null). length *MUST BE MORE THAN 2* !
 **********************************************************/

char *sam_encode_acct_ctrl(uint16 acct_ctrl, size_t length)
{
	static fstring acct_str;
	size_t i = 0;

	acct_str[i++] = '[';

	if (acct_ctrl & ACB_PWNOTREQ ) acct_str[i++] = 'N';
	if (acct_ctrl & ACB_DISABLED ) acct_str[i++] = 'D';
	if (acct_ctrl & ACB_HOMDIRREQ) acct_str[i++] = 'H';
	if (acct_ctrl & ACB_TEMPDUP  ) acct_str[i++] = 'T'; 
	if (acct_ctrl & ACB_NORMAL   ) acct_str[i++] = 'U';
	if (acct_ctrl & ACB_MNS      ) acct_str[i++] = 'M';
	if (acct_ctrl & ACB_WSTRUST  ) acct_str[i++] = 'W';
	if (acct_ctrl & ACB_SVRTRUST ) acct_str[i++] = 'S';
	if (acct_ctrl & ACB_AUTOLOCK ) acct_str[i++] = 'L';
	if (acct_ctrl & ACB_PWNOEXP  ) acct_str[i++] = 'X';
	if (acct_ctrl & ACB_DOMTRUST ) acct_str[i++] = 'I';

	for ( ; i < length - 2 ; i++ )
		acct_str[i] = ' ';

	i = length - 2;
	acct_str[i++] = ']';
	acct_str[i++] = '\0';

	return acct_str;
}     

/**********************************************************
 Decode the account control bits from a string.
 **********************************************************/

uint16 sam_decode_acct_ctrl(const char *p)
{
	uint16 acct_ctrl = 0;
	BOOL finished = False;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[')
		return 0;

	for (p++; *p && !finished; p++) {
		switch (*p) {
			case 'N': { acct_ctrl |= ACB_PWNOTREQ ; break; /* 'N'o password. */ }
			case 'D': { acct_ctrl |= ACB_DISABLED ; break; /* 'D'isabled. */ }
			case 'H': { acct_ctrl |= ACB_HOMDIRREQ; break; /* 'H'omedir required. */ }
			case 'T': { acct_ctrl |= ACB_TEMPDUP  ; break; /* 'T'emp account. */ } 
			case 'U': { acct_ctrl |= ACB_NORMAL   ; break; /* 'U'ser account (normal). */ } 
			case 'M': { acct_ctrl |= ACB_MNS      ; break; /* 'M'NS logon user account. What is this ? */ } 
			case 'W': { acct_ctrl |= ACB_WSTRUST  ; break; /* 'W'orkstation account. */ } 
			case 'S': { acct_ctrl |= ACB_SVRTRUST ; break; /* 'S'erver account. */ } 
			case 'L': { acct_ctrl |= ACB_AUTOLOCK ; break; /* 'L'ocked account. */ } 
			case 'X': { acct_ctrl |= ACB_PWNOEXP  ; break; /* No 'X'piry on password */ } 
			case 'I': { acct_ctrl |= ACB_DOMTRUST ; break; /* 'I'nterdomain trust account. */ }
            case ' ': { break; }
			case ':':
			case '\n':
			case '\0': 
			case ']':
			default:  { finished = True; }
		}
	}

	return acct_ctrl;
}

/*************************************************************
 Routine to set 32 hex password characters from a 16 byte array.
**************************************************************/

void sam_sethexpwd(char *p, const unsigned char *pwd, uint16 acct_ctrl)
{
	if (pwd != NULL) {
		int i;
		for (i = 0; i < 16; i++)
			slprintf(&p[i*2], 3, "%02X", pwd[i]);
	} else {
		if (acct_ctrl & ACB_PWNOTREQ)
			safe_strcpy(p, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX", 33);
		else
			safe_strcpy(p, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 33);
	}
}

/*************************************************************
 Routine to get the 32 hex characters and turn them
 into a 16 byte array.
**************************************************************/

BOOL sam_gethexpwd(const char *p, unsigned char *pwd)
{
	int i;
	unsigned char   lonybble, hinybble;
	char           *hexchars = "0123456789ABCDEF";
	char           *p1, *p2;
	
	if (!p)
		return (False);
	
	for (i = 0; i < 32; i += 2) {
		hinybble = toupper(p[i]);
		lonybble = toupper(p[i + 1]);

		p1 = strchr(hexchars, hinybble);
		p2 = strchr(hexchars, lonybble);

		if (!p1 || !p2)
			return (False);

		hinybble = PTR_DIFF(p1, hexchars);
		lonybble = PTR_DIFF(p2, hexchars);

		pwd[i / 2] = (hinybble << 4) | lonybble;
	}
	return (True);
}
