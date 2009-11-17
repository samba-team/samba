/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
   
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

#ifndef __SMBTORTURE_H__
#define __SMBTORTURE_H__

#include "../lib/torture/torture.h"

struct smbcli_state;

extern struct torture_suite *torture_root;

extern int torture_entries;
extern int torture_seed;
extern int torture_numops;
extern int torture_failures;
extern int torture_numasync;

struct torture_test;
int torture_init(void);
bool torture_register_suite(struct torture_suite *suite);

/* Server Functionality Support */

/* Not all SMB server implementations support every aspect of the protocol.
 * To allow smbtorture to provide useful data when run against these servers we
 * define support parameters here, that will cause some tests to be skipped or
 * the correctness checking of some tests to be conditional.
 *
 * The idea is that different server implementations can be specified on the
 * command line such as "--target=win7" which will define the list of server
 * parameters that are not supported.  This is mostly a black list of
 * unsupported features with the default expectation being that all features are
 * supported.
 *
 * Because we use parametric options we do not need to define these parameters
 * anywhere, we just define the meaning of each here.*/

/* torture:cn_max_buffer_size
 *
 * This parameter specifies the maximum buffer size given in a change notify
 * request.  If an overly large buffer is requested by a client, the server
 * will return a STATUS_INVALID_PARAMETER.  The max buffer size on Windows
 * server pre-Win7 was 0x00080000.  In Win7 this was reduced to 0x00010000.
 */

/* torture:invalid_lock_range_support
 *
 * This parameter specifies whether the server will return
 * STATUS_INVALID_LOCK_RANGE in response to a LockingAndX request where the
 * combined offset and range overflow the 63-bit boundary.  On Windows servers
 * before Win7, this request would return STATUS_OK, but the actual lock
 * behavior was undefined. */

/* torture:sacl_support
 *
 * This parameter specifies whether the server supports the setting and
 * retrieval of System Access Control Lists.  This includes whether the server
 * supports the use of the SEC_FLAG_SYSTEM_SECURITY bit in the open access
 * mask.*/

#endif /* __SMBTORTURE_H__ */
