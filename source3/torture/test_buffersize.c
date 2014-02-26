/*
   Unix SMB/CIFS implementation.
   Test buffer sizes in cli_qpathinfo
   Copyright (C) Volker Lendecke 2012

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

#include "includes.h"
#include "torture/proto.h"
#include "libsmb/libsmb.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/secdesc.h"
#include "libcli/security/security.h"
#include "trans2.h"
#include "source3/libsmb/clirap.h"

bool run_qpathinfo_bufsize(int dummy)
{
	struct cli_state *cli = NULL;
	bool ret = false;
	int i;

	printf("Starting qpathinfo_bufsize\n");

	if (!torture_open_connection(&cli, 0)) {
		printf("torture_open_connection failed\n");
		goto fail;
	}

	for (i=0; i<500; i++) {
		uint8_t *rdata;
		uint32_t num_rdata;
		cli_qpathinfo(cli, cli, "\\", SMB_FILE_ALL_INFORMATION,
			      0, i, &rdata, &num_rdata);
	}

	ret = true;
fail:
	if (cli != NULL) {
		torture_close_connection(cli);
	}
	return ret;
}
