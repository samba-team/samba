/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Jeremy Allison 		1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 	1996-1998
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
 Read a SID from a file. This is for compatibility with the old MACHINE.SID
 style of SID storage
****************************************************************************/
static BOOL read_sid_from_file(const char *fname, DOM_SID *sid)
{
	char **lines;
	int numlines;
	BOOL ret;

	lines = file_lines_load(fname, &numlines);
	
	if (!lines || numlines < 1) {
		if (lines) file_lines_free(lines);
		return False;
	}
	
	ret = string_to_sid(sid, lines[0]);
	file_lines_free(lines);
	return ret;
}

/*
  generate a random sid - used to build our own sid if we don't have one
*/
static void generate_random_sid(DOM_SID *sid)
{
	int i;
	uchar raw_sid_data[12];

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
 Generate the global machine sid.
****************************************************************************/
BOOL pdb_generate_sam_sid(void)
{
	char *fname = NULL;
	char *domain_name;
	extern pstring global_myname;
	extern fstring global_myworkgroup;

	generate_wellknown_sids();

	/* the local SAMR sid is based on the workgroup only when we are a DC */
	switch (lp_server_role()) {
	case ROLE_DOMAIN_PDC:
	case ROLE_DOMAIN_BDC:
		domain_name = global_myworkgroup;
		break;
	default:
		domain_name = global_myname;
		break;
	}

	if (secrets_fetch_domain_sid(domain_name, &global_sam_sid)) {
		return True;
	}

	/* check for an old MACHINE.SID file for backwards compatibility */
	asprintf(&fname, "%s/MACHINE.SID", lp_private_dir());
	if (read_sid_from_file(fname, &global_sam_sid)) {
		/* remember it for future reference and unlink the old MACHINE.SID */
		if (secrets_store_domain_sid(domain_name, &global_sam_sid)) {
			unlink(fname);
		}
		return True;
	}

	/* we don't have the SID in secrets.tdb, we will need to
           generate one and save it */
	generate_random_sid(&global_sam_sid);

	return secrets_store_domain_sid(domain_name, &global_sam_sid);
}   
