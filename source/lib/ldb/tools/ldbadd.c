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
 *  Component: ldbadd
 *
 *  Description: utility to add records - modelled on ldapadd
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

		if (ldif->changetype != LDB_CHANGETYPE_ADD &&
		    ldif->changetype != LDB_CHANGETYPE_NONE) {
			fprintf(stderr, "Only CHANGETYPE_ADD records allowed\n");
			break;
		}

		ret = ldb_add(ldb, &ldif->msg);
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

	printf("Added %d records with %d failures\n", count, failures);
	
	return 0;
}
