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
#include "nterr.h"
#include "sids.h"

extern int DEBUGLEVEL;

uint32 initialise_dom_tdb(const DOM_SID *sid)
{
	pstring usr;
	pstring usg;
	pstring usa;
	pstring grp;
	pstring als;
	fstring tmp;

	sid_to_string(tmp, sid);

	slprintf(usr, sizeof(usr)-1, "%s.usr.tdb", tmp);
	slprintf(usg, sizeof(usg)-1, "%s.usg.tdb", tmp);
	slprintf(usa, sizeof(usa)-1, "%s.usa.tdb", tmp);
	slprintf(grp, sizeof(grp)-1, "%s.grp.tdb", tmp);
	slprintf(als, sizeof(als)-1, "%s.als.tdb", tmp);

	/* create if not-exist with root-readwrite, all others read */
	if (tdb_close(tdb_open(passdb_path(usr),0,0,O_RDWR|O_CREAT,0644)) ||
	    tdb_close(tdb_open(passdb_path(usg),0,0,O_RDWR|O_CREAT,0644)) ||
	    tdb_close(tdb_open(passdb_path(usa),0,0,O_RDWR|O_CREAT,0644)) ||
	    tdb_close(tdb_open(passdb_path(grp),0,0,O_RDWR|O_CREAT,0644)) ||
	    tdb_close(tdb_open(passdb_path(als),0,0,O_RDWR|O_CREAT,0644)))
	{
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_NOPROBLEMO;
}

static BOOL create_domain(TDB_CONTEXT *tdb, const char* domain,
				const DOM_SID *sid)
{
	prs_struct key;
	prs_struct data;
	UNISTR2 uni_domain;
	DOM_SID s;

	sid_copy(&s, sid);

	DEBUG(10,("creating domain %s\n", domain));

	make_unistr2(&uni_domain, domain, strlen(domain));

	prs_init(&key, 0, 4, False);
	prs_init(&data, 0, 4, False);

	if (!smb_io_unistr2("dom", &uni_domain, True, &key, 0) ||
	    !smb_io_dom_sid("sid", &s, &data, 0) ||
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

static uint32 init_dom_tdbs(const DOM_SID *sam_sid)
{
	uint32 status;

	DEBUG(0,("initialise_dom_tdb: TODO - create BUILTIN domain aliases\n"));

	status = initialise_dom_tdb(sam_sid);
	if (status != 0x0) return status;
	status = initialise_dom_tdb(&global_sid_S_1_5_20);
	return status;
}

/***************************************************************************
 create various sam tdb databases, initialising them as necessary.
 ***************************************************************************/
uint32 initialise_sam_tdb( const char* sam_name, const DOM_SID *sam_sid)
{
	pstring srv_db_name;
	fstring dom_name;
	TDB_CONTEXT *sam_tdb;

	sam_tdb = tdb_open(passdb_path("sam.tdb"), 0, 0, O_RDWR, 0644);

	if (sam_tdb != NULL)
	{
		tdb_close(sam_tdb);
		return init_dom_tdbs(sam_sid);
	}

	DEBUG(0,("initialise_sam_tdb: creating %s\n", srv_db_name));

	/* create if not-exist with root-readwrite, all others read */
	sam_tdb = tdb_open(passdb_path("sam.tdb"),0,0,O_RDWR|O_CREAT,0644);

	if (sam_tdb == NULL)
	{
		return NT_STATUS_ACCESS_DENIED;
	}

	fstrcpy(dom_name, sam_name);
	strupper(dom_name);

	if (!create_domain(sam_tdb, sam_name, sam_sid) ||
	    !create_domain(sam_tdb, "BUILTIN", &global_sid_S_1_5_20))
	{
		tdb_close(sam_tdb);
		return NT_STATUS_ACCESS_DENIED;
	}

	tdb_close(sam_tdb);
	return init_dom_tdbs(sam_sid);
}

BOOL pwdbsam_initialise(void)
{
	return initialise_sam_tdb(global_sam_name, &global_sam_sid) ==
	       NT_STATUS_NOPROBLEMO;
}
