 /* 
   Unix SMB/CIFS implementation.

   a utility to add elements to a ldb

   Copyright (C) Andrew Tridgell 2004
   
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

 int main(void)
{
	static struct ldb_context *ldb;
	struct ldb_message *msg;
	int ret;
	int count=0, failures=0;

	ldb = ltdb_connect("tdb://test.ldb", 0, NULL);

	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	while ((msg = ldif_read(stdin))) {
		ret = ldb->ops->add(ldb, msg);
		if (ret != 0) {
			fprintf(stderr, "Failed to add record '%s'\n", msg->dn);
			failures++;
		} else {
			count++;
		}
		ldif_read_free(msg);
	}

	ldb->ops->close(ldb);

	printf("Added %d records with %d failures\n", count, failures);
	
	return 0;
}
