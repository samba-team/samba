/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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

extern int DEBUGLEVEL;

BOOL tdb_delete_secret(TDB_CONTEXT * tdb, const UNISTR2 * uk)
{
	prs_struct key;
	UNISTR2 k;
	pstring tmp;

	copy_unistr2(&k, uk);

	unistr2_to_ascii(tmp, uk, sizeof(tmp) - 1);
	DEBUG(10, ("delete secret %s\n", tmp));

	prs_init(&key, 0, 4, False);
	if (!smb_io_unistr2("key", &k, 1, &key, 0))
	{
		return False;
	}

	prs_tdb_delete(tdb, &key);

	prs_free_data(&key);

	return True;
}

BOOL tdb_lookup_secret(TDB_CONTEXT * tdb, const UNISTR2 * uk,
		       LSA_SECRET ** usr)
{
	prs_struct key;
	prs_struct data;
	UNISTR2 k = *uk;
	pstring tmp;

	copy_unistr2(&k, uk);

	if (usr != NULL)
	{
		(*usr) = g_new(LSA_SECRET, 1);
		if ((*usr) == NULL)
		{
			return False;
		}
		ZERO_STRUCTP((*usr));
	}

	unistr2_to_ascii(tmp, uk, sizeof(tmp) - 1);
	DEBUG(10, ("lookup secret %s\n", tmp));

	prs_init(&key, 0, 4, False);
	if (!smb_io_unistr2("key", &k, 1, &key, 0))
	{
		prs_free_data(&key);
		safe_free((*usr));
		return False;
	}

	prs_tdb_fetch(tdb, &key, &data);

	if (prs_buf_len(&data) == 0x0)
	{
		if (usr != NULL)
		{
			safe_free((*usr));
		}
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}


	if (usr != NULL)
	{
		if (!lsa_io_secret("usr", (*usr), &data, 0))
		{
			prs_free_data(&key);
			prs_free_data(&data);
			safe_free((*usr));
			return False;
		}
	}

	prs_free_data(&key);
	prs_free_data(&data);

	return True;
}

BOOL tdb_store_secret(TDB_CONTEXT * tdb, const UNISTR2 * uk, LSA_SECRET * usr)
{
	prs_struct key;
	prs_struct data;
	UNISTR2 k;
	pstring tmp;

	copy_unistr2(&k, uk);

	unistr2_to_ascii(tmp, uk, sizeof(tmp) - 1);
	DEBUG(10, ("storing secret %s\n", tmp));


	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!smb_io_unistr2("key", &k, 1, &key, 0) ||
	    !lsa_io_secret("usr", usr, &data, 0) ||
	    prs_tdb_store(tdb, TDB_REPLACE, &key, &data) != 0)
	{
		prs_free_data(&key);
		prs_free_data(&data);
		return False;
	}

	prs_free_data(&key);
	prs_free_data(&data);
	return True;
}

TDB_CONTEXT *open_secret_db(int perms)
{
	extern fstring global_myworkgroup;
	extern pstring global_myname;
	fstring domsec;
	fstring domname;
	fstring srvname;

	fstrcpy(domname, global_myworkgroup);
	fstrcpy(srvname, global_myname);
	strupper(domname);
	strupper(srvname);

	slprintf(domsec, sizeof(domsec) - 1, "%s.%s.tdb", domname, srvname);

	return tdb_open(lock_path(domsec), 0, 0, perms, 0600);
}

BOOL secret_init_db(void)
{
	extern fstring global_myworkgroup;
	extern pstring global_myname;
	uchar trust_passwd[16];
	fstring domname;
	fstring srvname;
	NTTIME crt;
	UNISTR2 name;
	char *an = "$MACHINE.ACC";
	LSA_SECRET sec;
	TDB_CONTEXT *tdb;
	BOOL ret = False;

	fstrcpy(domname, global_myworkgroup);
	fstrcpy(srvname, global_myname);
	strupper(domname);
	strupper(srvname);

	tdb = open_secret_db(O_RDWR);

	if (tdb != NULL)
	{
		DEBUG(10, ("secret_init_db: opened\n"));
		return True;
	}

	tdb = open_secret_db(O_RDWR | O_CREAT);

	if (tdb == NULL)
	{
		DEBUG(0, ("secret_init_db: failed\n"));
		return False;
	}

	DEBUG(10, ("secret_init_db: opened first time: initialising.\n"));

	generate_random_buffer(trust_passwd, 16, True);
	unix_to_nt_time(&crt, time(NULL));

	make_unistr2(&name, an, strlen(an));
	ZERO_STRUCT(sec);

	sec.curinfo.ptr_value = 1;
	sec.curinfo.value.ptr_secret = 0x1;
	make_strhdr2(&sec.curinfo.value.hdr_secret, 24, 24, 1);

	sec.curinfo.value.enc_secret.str_max_len = 24;
	sec.curinfo.value.enc_secret.undoc = 0;
	sec.curinfo.value.enc_secret.str_str_len = 24;

	SIVAL(sec.curinfo.value.enc_secret.buffer, 0, 16);
	SIVAL(sec.curinfo.value.enc_secret.buffer, 4, 0x01);
	memcpy(sec.curinfo.value.enc_secret.buffer + 8, trust_passwd, 16);

	sec.oldinfo.ptr_update = 1;
	sec.oldinfo.last_update = crt;

	sec.curinfo.ptr_update = 1;
	sec.curinfo.last_update = crt;

	ret = tdb_store_secret(tdb, &name, &sec);

	tdb_close(tdb);

	return ret;
}
