/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldbmodify
 *
 *  Description: utility to modify records - modelled on ldapmodify
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"

 int main(void)
{
	static struct ldb_context *ldb;
	struct ldb_ldif *ldif;
	int ret;
	int count=0, failures=0;
	const char *ldb_url;

	ldb_url = getenv("LDB_URL");
	if (!ldb_url) {
		ldb_url = "tdb://test.ldb";
	}

	ldb = ldb_connect(ldb_url, 0, NULL);

	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	while ((ldif = ldif_read_file(stdin))) {
		switch (ldif->changetype) {
		case LDB_CHANGETYPE_NONE:
		case LDB_CHANGETYPE_ADD:
			ret = ldb_add(ldb, &ldif->msg);
			break;
		case LDB_CHANGETYPE_DELETE:
			ret = ldb_delete(ldb, ldif->msg.dn);
			break;
		case LDB_CHANGETYPE_MODIFY:
			ret = ldb_modify(ldb, &ldif->msg);
			break;
		}
		if (ret != 0) {
			fprintf(stderr, "ERR: \"%s\" on DN %s\n", 
				ldb_errstring(ldb), ldif->msg.dn);
			failures++;
		} else {
			count++;
		}
		ldif_read_free(ldif);
	}

	ldb_close(ldb);

	printf("Modified %d records with %d failures\n", count, failures);
	
	return 0;
}
