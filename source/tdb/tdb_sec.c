/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   a tdb database with record level security.
   Copyright (C) Andrew Tridgell              2000
   Copyright (C) Luke Kenneth Casson Leighton 2000
   
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

/*
 * function prototypes:
 *
 * int tdbsec_setsec(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA secdata)
 *
 *
 * int tdbsec_delsec(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA secdata)
 *
 *
 * TDB_DATA tdbsec_fetch(TDB_CONTEXT *tdb, TDB_DATA key, 
 *                       int (*sec_check)(TDB_DATA , void *), void *arg)
 *
 *
 * int tdbsec_store(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA data,
 *                  int (*sec_check)(TDB_DATA , void *), void *arg)
 *
 *
 * example uses.  must set security first, followed by store actual data.
 *
 * tdbsec_setsec(tdb, key, security_data_for_key);
 * 
 * tdbsec_store (tdb, key, data, sec_store_check_fn());
 * tdbsec_fetch (tdb, key, data, sec_fetch_check_fn());
 * 
 * tdbsec_delete(tdb, key, sec_delete_check_fn());
 * tdbsec_delsec(tdb, key);
 *
 */

#include "includes.h"


#define SEC_KEY "SEC/"
#degine SEC_KEY_LEN 4

static TDB_DATA null_data;

static TDB_DATA tdbsec_genkey(TDB_DATA key)
{
	TDB_DATA key2;

	key2.dsize = SEC_KEY_LEN+key.dsize;
	key2.dptr = (char *)malloc(key2.dsize);
	if (!key2.dptr) return null_data;

	memcpy(key2.dptr, SEC_KEY, SEC_KEY_LEN);
	memcpy(key2.dptr + SEC_KEY_LEN, key.dptr, key.dsize);

	return key2;
}

static void tdbsec_free(TDB_DATA d)
{
	if (d.dptr) free(d.dptr);
}


TDB_DATA tdbsec_fetch(TDB_CONTEXT *tdb, TDB_DATA key, 
		      int (*sec_check)(TDB_DATA , void *), void *arg)
{
	TDB_DATA key2, data2;

	data2 = null_data;

	key2 = tdbsec_genkey(key);
	if (!key2.dptr) goto failed;

	data2 = tdb_fetch(tdb, key2);

	if (sec_check(data2, arg) != 0) {
		goto failed;
	}

	tdbsec_free(key2);
	tdbsec_free(data2);

	return tdb_fetch(tdb, key);

 failed:
	tdbsec_free(key2);
	tdbsec_free(data2);
	return null_data;
}

int tdbsec_delete(TDB_CONTEXT *tdb, TDB_DATA key,
		 int (*sec_check)(TDB_DATA , void *), void *arg)
{
	TDB_DATA key2, data2;

	data2 = null_data;

	key2 = tdbsec_genkey(key);
	if (!key2.dptr) goto failed;

	data2 = tdb_fetch(tdb, key2);

	if (sec_check(data2, arg) != 0) {
		goto failed;
	}

	tdbsec_free(key2);
	tdbsec_free(data2);

	return tdb_delete(tdb, key);

 failed:
	tdbsec_free(key2);
	tdbsec_free(data2);
	return -1;
}

int tdbsec_store(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA data,
		 int (*sec_check)(TDB_DATA , void *), void *arg)
{
	TDB_DATA key2, data2;

	data2 = null_data;

	key2 = tdbsec_genkey(key);
	if (!key2.dptr) goto failed;

	data2 = tdb_fetch(tdb, key2);

	if (sec_check(data2, arg) != 0) {
		goto failed;
	}

	tdbsec_free(key2);
	tdbsec_free(data2);

	return tdb_store(tdb, key, data, TDB_REPLACE);

 failed:
	tdbsec_free(key2);
	tdbsec_free(data2);
	return -1;
}


int tdbsec_setsec(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA secdata)
{
	int ret;
	TDB_DATA key2;

	key2 = tdbsec_genkey(key);
	if (!key2.dptr) return -1;
	
	ret = tdb_store(tdb, key2, secdata, TDB_REPLACE);
	
	tdbsec_free(key2);
	return ret;
}

int tdbsec_delsec(TDB_CONTEXT *tdb, TDB_DATA key)
{
	int ret;
	TDB_DATA key2;

	key2 = tdbsec_genkey(key);
	if (!key2.dptr) return -1;
	
	ret = tdb_delete(tdb, key2);
	
	tdbsec_free(key2);
	return ret;
}

