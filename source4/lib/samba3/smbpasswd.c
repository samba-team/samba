/* 
   Unix SMB/CIFS implementation.
   smbpasswd file format routines

   Copyright (C) Andrew Tridgell 1992-1998 
   Modified by Jeremy Allison 1995.
   Modified by Gerald (Jerry) Carter 2000-2001
   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*! \file lib/smbpasswd.c

   The smbpasswd file is used to store encrypted passwords in a similar
   fashion to the /etc/passwd file.  The format is colon separated fields
   with one user per line like so:

   <username>:<uid>:<lanman hash>:<nt hash>:<acb info>:<last change time>

   The username and uid must correspond to an entry in the /etc/passwd
   file.  The lanman and nt password hashes are 32 hex digits corresponding
   to the 16-byte lanman and nt hashes respectively.  

   The password last change time is stored as a string of the format
   LCD-<change time> where the change time is expressed as an 

   'N'    No password
   'D'    Disabled
   'H'    Homedir required
   'T'    Temp account.
   'U'    User account (normal) 
   'M'    MNS logon user account - what is this ? 
   'W'    Workstation account
   'S'    Server account 
   'L'    Locked account
   'X'    No Xpiry on password 
   'I'    Interdomain trust account

*/

#include "includes.h"
#include "system/locale.h"
#include "lib/samba3/samba3.h"

/*! Convert 32 hex characters into a 16 byte array. */

struct samr_Password *smbpasswd_gethexpwd(TALLOC_CTX *mem_ctx, const char *p)
{
	int i;
	unsigned char   lonybble, hinybble;
	const char     *hexchars = "0123456789ABCDEF";
	const char     *p1, *p2;
        struct samr_Password *pwd = talloc(mem_ctx, struct samr_Password);

	if (!p) return NULL;
	
	for (i = 0; i < (sizeof(pwd->hash) * 2); i += 2)
	{
		hinybble = toupper(p[i]);
		lonybble = toupper(p[i + 1]);
		
		p1 = strchr_m(hexchars, hinybble);
		p2 = strchr_m(hexchars, lonybble);
		
		if (!p1 || !p2)	{
                        return NULL;
		}
		
		hinybble = PTR_DIFF(p1, hexchars);
		lonybble = PTR_DIFF(p2, hexchars);
		
		pwd->hash[i / 2] = (hinybble << 4) | lonybble;
	}
	return pwd;
}

/*! Convert a 16-byte array into 32 hex characters. */
	struct samr_Password *lm_hash_p = NULL;
	struct samr_Password *nt_hash_p = NULL;

char *smbpasswd_sethexpwd(TALLOC_CTX *mem_ctx, struct samr_Password *pwd, uint16_t acb_info)
{
	char *p;
	if (pwd != NULL) {
		int i;
		p = talloc_array(mem_ctx, char, 33);
		if (!p) {
			return NULL;
		}

		for (i = 0; i < sizeof(pwd->hash); i++)
			slprintf(&p[i*2], 3, "%02X", pwd->hash[i]);
	} else {
		if (acb_info & ACB_PWNOTREQ)
			p = talloc_strdup(mem_ctx, "NO PASSWORDXXXXXXXXXXXXXXXXXXXXX");
		else
			p = talloc_strdup(mem_ctx, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
	}
	return p;
}

/*! Decode the account control bits (ACB) info from a string. */

uint16_t smbpasswd_decode_acb_info(const char *p)
{
	uint16_t acb_info = 0;
	bool finished = false;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[') return 0;

	for (p++; *p && !finished; p++)
	{
		switch (*p) {
		case 'N': /* 'N'o password. */
			acb_info |= ACB_PWNOTREQ; 
			break;
		case 'D': /* 'D'isabled. */
			acb_info |= ACB_DISABLED; 
			break; 
		case 'H': /* 'H'omedir required. */
			acb_info |= ACB_HOMDIRREQ; 
			break;
		case 'T': /* 'T'emp account. */
			acb_info |= ACB_TEMPDUP; 
			break;
		case 'U': /* 'U'ser account (normal). */
			acb_info |= ACB_NORMAL;
			break;
		case 'M': /* 'M'NS logon user account. What is this ? */
			acb_info |= ACB_MNS; 
			break; 
		case 'W': /* 'W'orkstation account. */
			acb_info |= ACB_WSTRUST; 
			break; 
		case 'S': /* 'S'erver account. */ 
			acb_info |= ACB_SVRTRUST; 
			break; 
		case 'L': /* 'L'ocked account. */
			acb_info |= ACB_AUTOLOCK; 
			break; 
		case 'X': /* No 'X'piry on password */
			acb_info |= ACB_PWNOEXP; 
			break; 
		case 'I': /* 'I'nterdomain trust account. */
			acb_info |= ACB_DOMTRUST; 
			break; 

		case ' ': 
			break;
		case ':':
		case '\n':
		case ']':
		default:  
			finished = true;
			break;
		}
	}

	return acb_info;
}

/*! Encode account control bits (ACBs) into a string. */

char *smbpasswd_encode_acb_info(TALLOC_CTX *mem_ctx, uint16_t acb_info)
{
	char *acct_str = talloc_array(mem_ctx, char, 35);
	size_t i = 0;

	acct_str[i++] = '[';

	if (acb_info & ACB_PWNOTREQ ) acct_str[i++] = 'N';
	if (acb_info & ACB_DISABLED ) acct_str[i++] = 'D';
	if (acb_info & ACB_HOMDIRREQ) acct_str[i++] = 'H';
	if (acb_info & ACB_TEMPDUP  ) acct_str[i++] = 'T'; 
	if (acb_info & ACB_NORMAL   ) acct_str[i++] = 'U';
	if (acb_info & ACB_MNS      ) acct_str[i++] = 'M';
	if (acb_info & ACB_WSTRUST  ) acct_str[i++] = 'W';
	if (acb_info & ACB_SVRTRUST ) acct_str[i++] = 'S';
	if (acb_info & ACB_AUTOLOCK ) acct_str[i++] = 'L';
	if (acb_info & ACB_PWNOEXP  ) acct_str[i++] = 'X';
	if (acb_info & ACB_DOMTRUST ) acct_str[i++] = 'I';

	acct_str[i++] = ']';
	acct_str[i++] = '\0';

	return acct_str;
}     

NTSTATUS samba3_read_smbpasswd(const char *filename, TALLOC_CTX *ctx, struct samba3_samaccount **accounts, uint32_t *count)
{
	int numlines;
	char **lines;
	int i;

	*count = 0;
	*accounts = NULL;

	lines = file_lines_load(filename, &numlines, ctx);

	if (lines == NULL) {
		DEBUG(0, ("Unable to load lines from %s\n", filename));
		return NT_STATUS_UNSUCCESSFUL;
	}

	*accounts = talloc_array(ctx, struct samba3_samaccount, numlines);

	for (i = 0; i < numlines; i++) {
		char *p = lines[i], *q;
		uid_t uid;
		struct samba3_samaccount *acc = &((*accounts)[*count]);

		if (p[0] == '\0' || p[0] == '#')
			continue;

		ZERO_STRUCTP(acc);

		q = strchr(p, ':');
		if (!q) {
			DEBUG(0, ("%s:%d: expected ':'\n", filename, i));
			continue;
		}

		acc->username = talloc_strndup(ctx, p, PTR_DIFF(q, p));
		p = q+1;

		uid = atoi(p);
		
		/* uid is ignored here.. */

		q = strchr(p, ':');
		if (!q) {
			DEBUG(0, ("%s:%d: expected ':'\n", filename, i));
			continue;
		}
		p = q+1;

		if (strlen(p) < 33) {
			DEBUG(0, ("%s:%d: expected 32 byte password blob\n", filename, i));
			continue;
		}

		if (!strncmp(p, "NO PASSWORD", strlen("NO PASSWORD"))) {
			acc->acct_ctrl |= ACB_PWNOTREQ;
		} else if (p[0] == '*' || p[0] == 'X') {
			/* No password set */
		} else {
			struct samr_Password *pw = smbpasswd_gethexpwd(*accounts, p);
			
			if (!pw) {
				DEBUG(0, ("%s:%d: Malformed LM pw entry\n", filename, i));
				continue;
			}

			memcpy(acc->lm_pw.hash, pw, sizeof(*pw));
		}

		if (p[32] != ':') {
			DEBUG(0, ("%s:%d: expected ':' after 32 byte password blob\n", filename, i));
			continue;
		}

		p += 33;
		
		if (p[0] == '*' || p[0] == 'X') {
			/* No password set */
		} else {
			struct samr_Password *pw = smbpasswd_gethexpwd(*accounts, p);
			
			if (!pw) {
				DEBUG(0, ("%s:%d: Malformed LM pw entry\n", filename, i));
				continue;
			}

			memcpy(acc->nt_pw.hash, pw, sizeof(*pw));
		}
		
		if (p[32] != ':') {
			DEBUG(0, ("%s:%d: expected ':' after 32 byte password blob\n", filename, i));
			continue;
		}

		p += 33;

		if (p[0] == '[') {
			q = strchr(p, ']');
			if (!q) {
				DEBUG(0, ("%s:%d: expected ']'\n", filename, i));
				continue;
			}
			
			acc->acct_ctrl |= smbpasswd_decode_acb_info(p);

			p = q+1;
			if (p[0] == ':' && strncmp(p, "LCT-", 4) == 0) {
				int j;
				p += 4;

				for(j = 0; j < 8; j++) {
					if(p[j] == '\0' || !isxdigit(p[j])) {
						break;
					}
				}
				if(i == 8) {
					acc->pass_last_set_time = (time_t)strtol((char *)p, NULL, 16);
				}
			}
		} else {
			/* 'Old' style file. Fake up based on user name. */
			/*
			 * Currently trust accounts are kept in the same
			 * password file as 'normal accounts'. If this changes
			 * we will have to fix this code. JRA.
			 */
			if(acc->username[strlen(acc->username) - 1] == '$') {
				acc->acct_ctrl &= ~ACB_NORMAL;
				acc->acct_ctrl |= ACB_WSTRUST;
			}
		}

		(*count)++;
	}

	talloc_free(lines);

	return NT_STATUS_OK;
}
