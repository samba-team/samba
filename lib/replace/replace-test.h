#ifndef __LIB_REPLACE_REPLACE_TEST_H__
#define __LIB_REPLACE_REPLACE_TEST_H__

/*
   Unix SMB/CIFS implementation.

   (C) 2011 Samba Team.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

bool torture_local_replace(struct torture_context *ctx);
int libreplace_test_strptime(void);
int test_readdir_os2_delete(void);
int getifaddrs_test(void);

#endif /* __LIB_REPLACE_REPLACE_TEST_H__ */

