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
 *  Component: ldbdel
 *
 *  Description: utility to delete records - modelled on ldapdelete
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"

 int main(int argc, const char *argv[])
{
	static struct ldb_context *ldb;
	int ret, i;
	const char *ldb_url;

	ldb_url = getenv("LDB_URL");
	if (!ldb_url) {
		ldb_url = "tdb://test.ldb";
	}


	if (argc < 2) {
		printf("Usage: ldbdel <dn...>\n");
		exit(1);
	}

	ldb = ldb_connect(ldb_url, 0, NULL);
	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	for (i=1;i<argc;i++) {
		ret = ldb_delete(ldb, argv[i]);
		if (ret != 0) {
			printf("delete of '%s' failed\n", argv[i]);
		}
	}

	ldb_close(ldb);
	return 0;
}
