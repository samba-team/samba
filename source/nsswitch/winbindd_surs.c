/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   Winbind daemon for ntdom nss module
   Copyright (C) Tim Potter 2000
   
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
#include "winbindd.h"

/* Wrapper around "standard" surs sid to unixid function */

BOOL winbindd_surs_sam_sid_to_unixid(DOM_SID *sid, uint32 type, uint32 *id)
{
    fstring sid_str;
    BOOL result;

    result = surs_sam_sid_to_unixid(sid, type, id, False);

    sid_to_string(sid_str, sid);
    DEBUG(0, ("surs_sam_sid_to_unixid: %s type %s -> %d\n", sid_str,
              (type == SID_NAME_USER) ? "user" : (
                  (type == SID_NAME_ALIAS) ? "alias" : (
                      (type == SID_NAME_DOM_GRP) ? "domain group" : "?")),
              (result ? ((id != NULL) ? *id : -2) : -1)));

    return result;
}

/* Wrapper around "standard" surs unixd to sid function */

BOOL winbindd_surs_unixid_to_sam_sid(uint32 id, uint32 type, DOM_SID *sid,
                                        BOOL create)
{
    fstring sid_str;
    BOOL result;

    result = surs_unixid_to_sam_sid(id, type, sid, create);

    if (sid) sid_to_string(sid_str, sid);

    DEBUG(0, ("surs_unixid_to_sam_sid: %d type %s -> %s\n", id,
              (type == SID_NAME_USER) ? "user" : (
                  (type == SID_NAME_ALIAS) ? "alias" : (
                      (type == SID_NAME_DOM_GRP) ? "domain group" : "?")),
              sid ? sid_str : "NULL"));

    return result;
}
