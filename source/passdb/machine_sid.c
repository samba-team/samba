/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Jeremy Allison 		1996-2002
   Copyright (C) Andrew Tridgell		2002
   Copyright (C) Gerald (Jerry) Carter		2000
      
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

/****************************************************************************
 Read the machine SID from a file.
****************************************************************************/

static BOOL read_sid_from_file(char *fname, DOM_SID *sid)
{
	char **lines;
	int numlines;
	BOOL ret;

	lines = file_lines_load(fname, &numlines, False);

	if (!lines || numlines < 1) {
		if (lines)
			file_lines_free(lines);
		return False;
	}

	ret = string_to_sid(sid, lines[0]);
	if (!ret)
		DEBUG(0,("read_sid_from_file: Failed to convert machine SID. (%s)\n", lines[0]));
	file_lines_free(lines);
	return ret;
}

/****************************************************************************
 Generate a random sid - used to build our own sid if we don't have one.
****************************************************************************/

static void generate_random_sid(DOM_SID *sid)
{
	int i;
	unsigned char raw_sid_data[12];

	memset((char *)sid, '\0', sizeof(*sid));
	sid->sid_rev_num = 1;
	sid->id_auth[5] = 5;
	sid->num_auths = 0;
	sid->sub_auths[sid->num_auths++] = 21;

	generate_random_buffer(raw_sid_data, 12, True);
	for (i = 0; i < 3; i++)
		sid->sub_auths[sid->num_auths++] = IVAL(raw_sid_data, i*4);
}

/****************************************************************************
 Generate the global machine sid. Look for the MACHINE.SID file first, if
 not found then look in smb.conf and use it to create the MACHINE.SID file.
 Note this function will be replaced soon. JRA.
****************************************************************************/

BOOL pdb_generate_sam_sid(void)
{
	char *fname = NULL;
	extern pstring global_myname;
	extern fstring global_myworkgroup;
	BOOL is_dc = False;
	pstring priv_dir;

	generate_wellknown_sids();

	switch (lp_server_role()) {
	case ROLE_DOMAIN_PDC:
	case ROLE_DOMAIN_BDC:
		is_dc = True;
		break;
	default:
		is_dc = False;
		break;
	}

	if (secrets_fetch_domain_sid(global_myname, &global_sam_sid)) {
		DOM_SID domain_sid;

		/* We got our sid. If not a pdc/bdc, we're done. */
		if (!is_dc)
			return True;

		if (!secrets_fetch_domain_sid(global_myworkgroup, &domain_sid)) {

			/* No domain sid and we're a pdc/bdc. Store it */

			if (!secrets_store_domain_sid(global_myworkgroup, &global_sam_sid)) {
				DEBUG(0,("pdb_generate_sam_sid: Can't store domain SID as a pdc/bdc.\n"));
				return False;
			}
			return True;
		}

		if (!sid_equal(&domain_sid, &global_sam_sid)) {

			/* Domain name sid doesn't match global sam sid. Re-store global sam sid as domain sid. */

			DEBUG(0,("pdb_generate_sam_sid: Mismatched SIDs as a pdc/bdc.\n"));
			if (!secrets_store_domain_sid(global_myworkgroup, &global_sam_sid)) {
				DEBUG(0,("pdb_generate_sam_sid: Can't re-store domain SID as a pdc/bdc.\n"));
				return False;
			}
			return True;
		}

		return True;
	}

	/* check for an old MACHINE.SID file for backwards compatibility */
	get_private_directory(priv_dir);
	asprintf(&fname, "%s/MACHINE.SID", priv_dir);

	if (read_sid_from_file(fname, &global_sam_sid)) {
		/* remember it for future reference and unlink the old MACHINE.SID */
		if (!secrets_store_domain_sid(global_myname, &global_sam_sid)) {
			DEBUG(0,("pdb_generate_sam_sid: Failed to store SID from file.\n"));
			SAFE_FREE(fname);
			return False;
		}
		unlink(fname);
		if (is_dc) {
			if (!secrets_store_domain_sid(global_myworkgroup, &global_sam_sid)) {
				DEBUG(0,("pdb_generate_sam_sid: Failed to store domain SID from file.\n"));
				SAFE_FREE(fname);
				return False;
			}
		}

		/* Stored the old sid from MACHINE.SID successfully.
			Patch from Stefan "metze" Metzmacher <metze@metzemix.de>*/
		SAFE_FREE(fname);
		return True;
	}

	SAFE_FREE(fname);

	/* we don't have the SID in secrets.tdb, we will need to
		generate one and save it */
	generate_random_sid(&global_sam_sid);
	DEBUG(10, ("Generated random SID ...\n"));
	if (!secrets_store_domain_sid(global_myname, &global_sam_sid)) {
		DEBUG(0,("pdb_generate_sam_sid: Failed to store generated machine SID.\n"));
		return False;
	}
	if (is_dc) {
		if (!secrets_store_domain_sid(global_myworkgroup, &global_sam_sid)) {
			DEBUG(0,("pdb_generate_sam_sid: Failed to store generated domain SID.\n"));
			return False;
		}
	}

	return True;
}
