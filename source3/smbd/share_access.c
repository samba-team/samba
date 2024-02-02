/*
   Unix SMB/CIFS implementation.
   Check access based on valid users, read list and friends
   Copyright (C) Volker Lendecke 2005

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/security/security.h"

/*
 * Check whether a user is contained in the list provided.
 *
 * Please note that the user name and share names passed in here mainly for
 * the substitution routines that expand the parameter values, the decision
 * whether a user is in the list is done after a lookup_name on the expanded
 * parameter value, solely based on comparing the SIDs in token.
 *
 * The other use is the netgroup check when using @group or &group.
 */

bool token_contains_name_in_list(const char *username,
				 const char *domain,
				 const char *sharename,
				 const struct security_token *token,
				 const char **list,
				 bool *match)
{
	*match = false;
	if (list == NULL) {
		return true;
	}
	while (*list != NULL) {
		TALLOC_CTX *frame = talloc_stackframe();
		bool ok;

	        ok = token_contains_name(frame, username, domain, sharename,
					 token, *list, match);
		TALLOC_FREE(frame);
		if (!ok) {
			return false;
		}
		if (*match) {
			return true;
		}
		list += 1;
	}
	return true;
}

/*
 * Check whether the user described by "token" has access to share snum.
 *
 * This looks at "invalid users" and "valid users".
 *
 * Please note that the user name and share names passed in here mainly for
 * the substitution routines that expand the parameter values, the decision
 * whether a user is in the list is done after a lookup_name on the expanded
 * parameter value, solely based on comparing the SIDs in token.
 *
 * The other use is the netgroup check when using @group or &group.
 */

bool user_ok_token(const char *username, const char *domain,
		   const struct security_token *token, int snum)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	bool match;
	bool ok;

	if (lp_invalid_users(snum) != NULL) {
		ok = token_contains_name_in_list(username, domain,
						 lp_servicename(talloc_tos(), lp_sub, snum),
						 token,
						 lp_invalid_users(snum),
						 &match);
		if (!ok) {
			return false;
		}
		if (match) {
			DEBUG(10, ("User %s in 'invalid users'\n", username));
			return False;
		}
	}

	if (lp_valid_users(snum) != NULL) {
		ok = token_contains_name_in_list(username, domain,
						 lp_servicename(talloc_tos(), lp_sub, snum),
						 token,
						 lp_valid_users(snum),
						 &match);
		if (!ok) {
			return false;
		}
		if (!match) {
			DEBUG(10, ("User %s not in 'valid users'\n",
				   username));
			return False;
		}
	}

	DEBUG(10, ("user_ok_token: share %s is ok for unix user %s\n",
		   lp_servicename(talloc_tos(), lp_sub, snum), username));

	return True;
}

/*
 * Check whether the user described by "token" is restricted to read-only
 * access on share snum.
 *
 * This looks at "read list", "write list" and "read only".
 *
 * Please note that the user name and share names passed in here mainly for
 * the substitution routines that expand the parameter values, the decision
 * whether a user is in the list is done after a lookup_name on the expanded
 * parameter value, solely based on comparing the SIDs in token.
 *
 * The other use is the netgroup check when using @group or &group.
 */

bool is_share_read_only_for_token(const char *username,
				  const char *domain,
				  const struct security_token *token,
				  connection_struct *conn,
				  bool *_read_only)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	int snum = SNUM(conn);
	bool read_only = conn->read_only;
	bool match;
	bool ok;

	if (lp_read_list(snum) != NULL) {
		ok = token_contains_name_in_list(username, domain,
						 lp_servicename(talloc_tos(), lp_sub, snum),
						 token,
						 lp_read_list(snum),
						 &match);
		if (!ok) {
			return false;
		}
		if (match) {
			read_only = true;
		}
	}

	if (lp_write_list(snum) != NULL) {
		ok = token_contains_name_in_list(username, domain,
						 lp_servicename(talloc_tos(), lp_sub, snum),
						 token,
						 lp_write_list(snum),
						 &match);
		if (!ok) {
			return false;
		}
		if (match) {
			read_only = false;
		}
	}

	DEBUG(10,("is_share_read_only_for_user: share %s is %s for unix user "
		  "%s\n", lp_servicename(talloc_tos(), lp_sub, snum),
		  read_only ? "read-only" : "read-write", username));

	*_read_only = read_only;
	return true;
}
