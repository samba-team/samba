/*
 *  Maintain rap vs spoolss jobids
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
   the printing backend revolves around a tdb database that stores the
   SMB view of the print queue

   The key for this database is a jobid - a internally generated number that
   uniquely identifies a print job

   reading the print queue involves two steps:
     - possibly running lpq and updating the internal database from that
     - reading entries from the database

   jobids are assigned when a job starts spooling.
*/

#include "rap_jobid.h"
#include <tdb.h>
#include "source3/include/util_tdb.h"
#include "lib/util/string_wrappers.h"

static TDB_CONTEXT *rap_tdb;
static uint16_t next_rap_jobid;
struct rap_jobid_key {
	fstring sharename;
	uint32_t  jobid;
};

/***************************************************************************
 Nightmare. LANMAN jobid's are 16 bit numbers..... We must map them to 32
 bit RPC jobids.... JRA.
***************************************************************************/

uint16_t pjobid_to_rap(const char* sharename, uint32_t jobid)
{
	uint16_t rap_jobid;
	TDB_DATA data, key;
	struct rap_jobid_key jinfo;
	uint8_t buf[2];

	DEBUG(10,("pjobid_to_rap: called.\n"));

	if (!rap_tdb) {
		/* Create the in-memory tdb. */
		rap_tdb = tdb_open_log(NULL, 0, TDB_INTERNAL, (O_RDWR|O_CREAT), 0644);
		if (!rap_tdb)
			return 0;
	}

	ZERO_STRUCT( jinfo );
	fstrcpy( jinfo.sharename, sharename );
	jinfo.jobid = jobid;
	key.dptr = (uint8_t *)&jinfo;
	key.dsize = sizeof(jinfo);

	data = tdb_fetch(rap_tdb, key);
	if (data.dptr && data.dsize == sizeof(uint16_t)) {
		rap_jobid = SVAL(data.dptr, 0);
		SAFE_FREE(data.dptr);
		DEBUG(10,("pjobid_to_rap: jobid %u maps to RAP jobid %u\n",
			(unsigned int)jobid, (unsigned int)rap_jobid));
		return rap_jobid;
	}
	SAFE_FREE(data.dptr);
	/* Not found - create and store mapping. */
	rap_jobid = ++next_rap_jobid;
	if (rap_jobid == 0)
		rap_jobid = ++next_rap_jobid;
	SSVAL(buf,0,rap_jobid);
	data.dptr = buf;
	data.dsize = sizeof(rap_jobid);
	tdb_store(rap_tdb, key, data, TDB_REPLACE);
	tdb_store(rap_tdb, data, key, TDB_REPLACE);

	DEBUG(10,("pjobid_to_rap: created jobid %u maps to RAP jobid %u\n",
		(unsigned int)jobid, (unsigned int)rap_jobid));
	return rap_jobid;
}

bool rap_to_pjobid(uint16_t rap_jobid, fstring sharename, uint32_t *pjobid)
{
	TDB_DATA data, key;
	uint8_t buf[2];

	DEBUG(10,("rap_to_pjobid called.\n"));

	if (!rap_tdb)
		return False;

	SSVAL(buf,0,rap_jobid);
	key.dptr = buf;
	key.dsize = sizeof(rap_jobid);
	data = tdb_fetch(rap_tdb, key);
	if ( data.dptr && data.dsize == sizeof(struct rap_jobid_key) )
	{
		struct rap_jobid_key *jinfo = (struct rap_jobid_key*)data.dptr;
		if (sharename != NULL) {
			fstrcpy( sharename, jinfo->sharename );
		}
		*pjobid = jinfo->jobid;
		DEBUG(10,("rap_to_pjobid: jobid %u maps to RAP jobid %u\n",
			(unsigned int)*pjobid, (unsigned int)rap_jobid));
		SAFE_FREE(data.dptr);
		return True;
	}

	DEBUG(10,("rap_to_pjobid: Failed to lookup RAP jobid %u\n",
		(unsigned int)rap_jobid));
	SAFE_FREE(data.dptr);
	return False;
}

void rap_jobid_delete(const char* sharename, uint32_t jobid)
{
	TDB_DATA key, data;
	uint16_t rap_jobid;
	struct rap_jobid_key jinfo;
	uint8_t buf[2];

	DEBUG(10,("rap_jobid_delete: called.\n"));

	if (!rap_tdb)
		return;

	ZERO_STRUCT( jinfo );
	fstrcpy( jinfo.sharename, sharename );
	jinfo.jobid = jobid;
	key.dptr = (uint8_t *)&jinfo;
	key.dsize = sizeof(jinfo);

	data = tdb_fetch(rap_tdb, key);
	if (!data.dptr || (data.dsize != sizeof(uint16_t))) {
		DEBUG(10,("rap_jobid_delete: cannot find jobid %u\n",
			(unsigned int)jobid ));
		SAFE_FREE(data.dptr);
		return;
	}

	DEBUG(10,("rap_jobid_delete: deleting jobid %u\n",
		(unsigned int)jobid ));

	rap_jobid = SVAL(data.dptr, 0);
	SAFE_FREE(data.dptr);
	SSVAL(buf,0,rap_jobid);
	data.dptr = buf;
	data.dsize = sizeof(rap_jobid);
	tdb_delete(rap_tdb, key);
	tdb_delete(rap_tdb, data);
}
